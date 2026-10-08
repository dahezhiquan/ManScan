package templates

import (
	"testing"

	"ManScan/internal/tests/testutils"
	"ManScan/pkg/model"
	"ManScan/pkg/model/types/severity"
	"ManScan/pkg/protocols/dns"
	"ManScan/pkg/protocols/http"
	"ManScan/pkg/protocols/ssl"
	"github.com/stretchr/testify/require"
)

func TestClusterTemplates(t *testing.T) {
	// state of whether template is flow or multiprotocol is stored in executerOptions i.e why we need to pass it
	execOptions := testutils.NewMockExecuterOptions(testutils.DefaultOptions, &testutils.TemplateInfo{
		ID:   "templateID",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	t.Run("http-cluster-get", func(t *testing.T) {
		tp1 := &Template{Path: "first.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}}
		tp2 := &Template{Path: "second.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}}
		tp1.Options = execOptions
		tp2.Options = execOptions
		tpls := []*Template{tp1, tp2}
		// cluster 0
		expected := []*Template{tp1, tp2}
		got := Cluster(tpls)[0]
		require.ElementsMatchf(t, expected, got, "different %v %v", len(expected), len(got))
	})
	t.Run("no-http-cluster", func(t *testing.T) {
		tp1 := &Template{Path: "first.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/random"}}}}
		tp2 := &Template{Path: "second.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/another"}}}}
		tp1.Options = execOptions
		tp2.Options = execOptions
		tpls := []*Template{tp1, tp2}
		expected := [][]*Template{{tp1}, {tp2}}
		got := Cluster(tpls)
		require.ElementsMatch(t, expected, got)
	})
	t.Run("dns-cluster", func(t *testing.T) {
		tp1 := &Template{Path: "first.yaml", RequestsDNS: []*dns.Request{{Name: "{{Hostname}}"}}}
		tp2 := &Template{Path: "second.yaml", RequestsDNS: []*dns.Request{{Name: "{{Hostname}}"}}}
		tp1.Options = execOptions
		tp2.Options = execOptions
		tpls := []*Template{tp1, tp2}
		// cluster 0
		expected := []*Template{tp1, tp2}
		got := Cluster(tpls)[0]
		require.ElementsMatch(t, got, expected)
	})
}

func TestClusterTemplatesCountsSSLRequests(t *testing.T) {
	testutils.Init(testutils.DefaultOptions)
	execOptions := testutils.NewMockExecuterOptions(testutils.DefaultOptions, &testutils.TemplateInfo{
		ID:   "templateID",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	tp1 := &Template{ID: "first", Path: "first.yaml", RequestsSSL: []*ssl.Request{{Address: "{{Host}}:443"}}}
	tp2 := &Template{ID: "second", Path: "second.yaml", RequestsSSL: []*ssl.Request{{Address: "{{Host}}:443"}}}
	tp1.Options = execOptions
	tp2.Options = execOptions
	require.NoError(t, tp1.RequestsSSL[0].Compile(execOptions))
	require.NoError(t, tp2.RequestsSSL[0].Compile(execOptions))

	clusteredTemplates, clusterCount, _ := ClusterTemplates([]*Template{tp1, tp2}, execOptions)

	require.Equal(t, 2, clusterCount)
	require.Len(t, clusteredTemplates, 1)
	require.Len(t, clusteredTemplates[0].RequestsSSL, 1)
	require.Equal(t, 1, clusteredTemplates[0].TotalRequests)
}
