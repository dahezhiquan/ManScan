package automaticscan

import (
	"os"
	"path/filepath"
	"testing"

	"ManScan/pkg/protocols/common/contextargs"
	"ManScan/pkg/protocols/dns"
	"ManScan/pkg/protocols/headless"
	httpprotocol "ManScan/pkg/protocols/http"
	"ManScan/pkg/protocols/network"
	"ManScan/pkg/templates"
	"github.com/stretchr/testify/require"
)

func TestNormalizeAppName(t *testing.T) {
	appName := normalizeAppName("JBoss")
	require.Equal(t, "jboss", appName, "could not get normalized name")

	appName = normalizeAppName("JBoss:2.3.5")
	require.Equal(t, "jboss", appName, "could not get normalized name")
}

func TestFilterAutomaticScanExecutionTags(t *testing.T) {
	tags := filterAutomaticScanExecutionTags([]string{"python", "detect", "DETECT", "uvicorn"})
	require.Equal(t, []string{"python", "uvicorn"}, tags)
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

func TestLoadAssetDomainFingerprintCache(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "fingerprints.json")
	data := `[
		{"target":"https://app.example.com/login","domain":"app.example.com:443","components":[{"domain":"app.example.com:443","app_name":"nginx:1.24.0","app_version":"1.24.0"}]},
		{"target":"https://empty.example.com/","domain":"empty.example.com:443","components":[]}
	]`
	require.NoError(t, os.WriteFile(cachePath, []byte(data), 0o600))
	t.Setenv(assetDomainFingerprintCacheEnv, cachePath)

	cache := loadAssetDomainFingerprintCache()
	require.Len(t, cache[assetDomainFingerprintCacheKey("https://app.example.com/login")].Components, 1)
	require.Len(t, cache[assetDomainFingerprintCacheKey("app.example.com:443")].Components, 1)
	_, ok := cache[assetDomainFingerprintCacheKey("https://empty.example.com/")]
	require.True(t, ok, "empty component cache should still mark wappalyzer as already probed")
}

func TestCachedHTTPProbeFailed(t *testing.T) {
	httpAlive := true
	httpDown := false
	service := &Service{fingerprintCache: map[string]assetDomainFingerprintCacheState{
		assetDomainFingerprintCacheKey("https://alive.example.com"): {
			HTTPAlive:      httpAlive,
			HTTPAliveKnown: true,
		},
		assetDomainFingerprintCacheKey("down.example.com:3306"): {
			HTTPAlive:      httpDown,
			HTTPAliveKnown: true,
		},
		assetDomainFingerprintCacheKey("legacy.example.com"): {},
	}}

	require.False(t, service.cachedHTTPProbeFailed(&contextargs.MetaInput{Input: "https://alive.example.com"}))
	require.True(t, service.cachedHTTPProbeFailed(&contextargs.MetaInput{Input: "down.example.com:3306"}))
	require.False(t, service.cachedHTTPProbeFailed(&contextargs.MetaInput{Input: "legacy.example.com"}))
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
