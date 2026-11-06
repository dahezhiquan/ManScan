package automaticscan

import (
	"os"
	"path/filepath"
	"testing"

	"ManScan/internal/tests/testutils"
	"ManScan/pkg/input/provider"
	"ManScan/pkg/protocols"
	"ManScan/pkg/protocols/common/assetdomainfingerprint"
	"ManScan/pkg/protocols/common/contextargs"
	"ManScan/pkg/protocols/dns"
	"ManScan/pkg/protocols/headless"
	httpprotocol "ManScan/pkg/protocols/http"
	"ManScan/pkg/protocols/network"
	"ManScan/pkg/templates"
	"github.com/stretchr/testify/require"
)

type requestEstimateProgress struct {
	testutils.MockProgressClient
	total      int64
	preCluster int64
}

func (p *requestEstimateProgress) SetTotal(total int64) { p.total = total }
func (p *requestEstimateProgress) SetPreClusterTotal(total int64) {
	p.preCluster = total
}

func TestNormalizeAppName(t *testing.T) {
	appName := normalizeAppName("JBoss")
	require.Equal(t, "jboss", appName, "could not get normalized name")

	appName = normalizeAppName("JBoss:2.3.5")
	require.Equal(t, "jboss", appName, "could not get normalized name")

	appName = normalizeAppName(" Apache HTTP Server:2.4.62 ")
	require.Equal(t, "apache http server", appName, "could not preserve the complete technology name")
}

func TestNormalizeWappalyzerTagsPreservesCompleteTechnologyNames(t *testing.T) {
	service := &Service{technologyMappings: map[string]string{
		"mapped server": "Mapped HTTP Server",
	}}

	tags := service.normalizeWappalyzerTags([]string{
		"Apache HTTP Server:2.4.62",
		"Vue.js",
		"ApacheGeneric",
		"Mapped Server:1.0",
		"apache http server",
	})

	require.Equal(t, []string{
		"apache http server",
		"vue.js",
		"apachegeneric",
		"mapped http server",
	}, tags)
}

func TestFilterAutomaticScanExecutionTags(t *testing.T) {
	tags := filterAutomaticScanExecutionTags([]string{"python", "detect", "DETECT", "uvicorn"})
	require.Equal(t, []string{"python", "uvicorn"}, tags)
}

func TestAutomaticFingerprintTagsMessage(t *testing.T) {
	require.Equal(t, "nginx, php", automaticFingerprintTagsMessage([]string{"nginx", "php"}))
	require.Equal(t,
		"apache http server, vue.js, apachegeneric",
		automaticFingerprintTagsMessage([]string{"apache http server", "vue.js", "apachegeneric"}),
	)
	require.Equal(t, "未发现", automaticFingerprintTagsMessage(nil))
	require.Equal(t, "未发现", automaticFingerprintTagsMessage([]string{}))
}

func TestMappedTemplateCountDeduplicatesAcrossTargets(t *testing.T) {
	targets := []mappedTarget{
		{finalTemplates: []*templates.Template{
			{ID: "http-misconfig"},
			{ID: "xss"},
		}},
		{finalTemplates: []*templates.Template{
			{ID: "http-misconfig"},
			{Path: "/custom/ssrf.yaml"},
			nil,
		}},
	}

	require.EqualValues(t, 3, mappedTemplateCount(targets))
}

func TestMappedRequestTotalsUseEffectiveNetworkTargets(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	request := &network.Request{Address: []string{"{{Hostname}}", "tls://{{Hostname}}"}, Port: "6379,6380"}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "redis-detect"})
	require.NoError(t, request.Compile(executerOpts))
	template := &templates.Template{ID: "redis-detect", TotalRequests: request.Requests(), RequestsNetwork: []*network.Request{request}}
	target := &contextargs.MetaInput{Input: "127.0.0.1:8379"}
	progress := &requestEstimateProgress{}
	service := &Service{
		opts:              &protocols.ExecutorOptions{Progress: progress},
		target:            provider.NewSimpleInputProviderWithUrls("", target.Input),
		techTemplates:     []*templates.Template{template},
		techTemplateStats: templateLoadStats{PreClusterTemplates: []*templates.Template{template}},
		totalGate:         newTotalGate(progress),
	}
	service.setMappedRequestTotal([]mappedTarget{{
		input:                target,
		finalTemplates:       []*templates.Template{template},
		preClusterRequests:   getRequestCountForInput([]*templates.Template{template}, target.Input),
		usedCachedWappalyzer: true,
	}})
	require.EqualValues(t, 4, progress.total)
	require.EqualValues(t, 4, progress.preCluster)
}

func TestLoadAssetDomainFingerprintCache(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "fingerprints.json")
	data := `[
		{"target":"https://app.example.com/login","domain":"app.example.com:443","components":[{"domain":"app.example.com:443","app_name":"nginx:1.24.0","app_version":"1.24.0"}]},
		{"target":"https://empty.example.com/","domain":"empty.example.com:443","components":[]}
	]`
	require.NoError(t, os.WriteFile(cachePath, []byte(data), 0o600))
	t.Setenv(assetdomainfingerprint.CacheEnv, cachePath)

	cache := assetdomainfingerprint.LoadFromEnv()
	state, ok := cache.Lookup("https://app.example.com/login")
	require.True(t, ok)
	require.Len(t, state.Components, 1)
	state, ok = cache.Lookup("app.example.com:443")
	require.True(t, ok)
	require.Len(t, state.Components, 1)
	_, ok = cache.Lookup("https://empty.example.com/")
	require.True(t, ok, "empty component cache should still mark wappalyzer as already probed")
}

func TestCachedHTTPProbeFailed(t *testing.T) {
	httpAlive := true
	httpDown := false
	service := &Service{fingerprintCache: assetdomainfingerprint.FromEntries([]assetdomainfingerprint.Entry{
		{
			Target:    "https://alive.example.com",
			HTTPAlive: &httpAlive,
		},
		{
			Target:    "down.example.com:3306",
			HTTPAlive: &httpDown,
		},
		{Target: "legacy.example.com"},
	})}

	require.False(t, service.cachedHTTPProbeFailed(&contextargs.MetaInput{Input: "https://alive.example.com"}))
	require.True(t, service.cachedHTTPProbeFailed(&contextargs.MetaInput{Input: "down.example.com:3306"}))
	require.False(t, service.cachedHTTPProbeFailed(&contextargs.MetaInput{Input: "legacy.example.com"}))
}

func TestGetTagsUsingCachedWappalyzerPreservesCompleteTechnologyNames(t *testing.T) {
	service := &Service{fingerprintCache: assetdomainfingerprint.FromEntries([]assetdomainfingerprint.Entry{
		{
			Target: "https://app.example.com",
			Components: []assetdomainfingerprint.Component{
				{AppName: "Apache HTTP Server:2.4.62"},
				{AppName: "Vue.js"},
				{AppName: "ApacheGeneric"},
			},
		},
	})}

	tags, ok := service.getTagsUsingCachedWappalyzer(&contextargs.MetaInput{Input: "https://app.example.com"})

	require.True(t, ok)
	require.Equal(t, []string{"apache http server", "vue.js", "apachegeneric"}, tags)
}

func TestFilterHTTPBasedTemplates(t *testing.T) {
	filtered := filterHTTPBasedTemplates([]*templates.Template{
		{ID: "http", RequestsHTTP: []*httpprotocol.Request{{}}},
		{ID: "headless", RequestsHeadless: []*headless.Request{{}}},
		{ID: "network", RequestsNetwork: []*network.Request{{}}},
	})

	require.Len(t, filtered, 1)
	require.Equal(t, "network", filtered[0].ID)
}

func TestIsHTTPFingerprintTemplate(t *testing.T) {
	require.True(t, isHTTPFingerprintTemplate(&templates.Template{RequestsHTTP: []*httpprotocol.Request{{}}}))
	require.True(t, isHTTPFingerprintTemplate(&templates.Template{RequestsHeadless: []*headless.Request{{}}}))
	require.True(t, isHTTPFingerprintTemplate(&templates.Template{
		RequestsDNS:  []*dns.Request{{}},
		RequestsHTTP: []*httpprotocol.Request{{}},
	}))
	require.False(t, isHTTPFingerprintTemplate(&templates.Template{RequestsNetwork: []*network.Request{{}}}))
}
