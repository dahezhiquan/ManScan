package customtemplates

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"ManScan/internal/tests/testutils"
	"ManScan/pkg/catalog/config"
	"ManScan/pkg/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/require"
)

func TestDownloadCustomTemplatesFromGitHub(t *testing.T) {
	// Capture output to check for rate limit errors
	outputBuffer := &bytes.Buffer{}
	gologger.DefaultLogger.SetWriter(&utils.CaptureWriter{Buffer: outputBuffer})
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	templatesDirectory := t.TempDir()
	config.DefaultConfig.SetTemplatesDir(templatesDirectory)

	options := testutils.DefaultOptions
	options.GitHubTemplateRepo = []string{"projectdiscovery/nuclei-templates-test"}

	ctm, err := NewCustomTemplatesManager(options)
	require.Nil(t, err, "could not create custom templates manager")

	ctm.Download(context.Background())

	// Check if output contains rate limit error and skip test if so
	output := outputBuffer.String()
	if strings.Contains(output, "API rate limit exceeded") {
		t.Skip("GitHub API rate limit exceeded, skipping test")
	}

	require.DirExists(t, filepath.Join(templatesDirectory, "github", "projectdiscovery", "nuclei-templates-test"), "cloned directory does not exists")
}
