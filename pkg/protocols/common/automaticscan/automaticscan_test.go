package automaticscan

import (
	"testing"

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
