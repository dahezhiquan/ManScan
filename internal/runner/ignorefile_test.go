package runner

import (
	"os"
	"strconv"
	"testing"

	"ManScan/pkg/catalog/config"
	"ManScan/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/require"
)

type ignoreFileLogRecord struct {
	message string
	level   levels.Level
}

type ignoreFileLogWriter struct {
	records []ignoreFileLogRecord
}

func (w *ignoreFileLogWriter) Write(data []byte, level levels.Level) {
	w.records = append(w.records, ignoreFileLogRecord{message: string(data), level: level})
}

func newIgnoreFileTestRunner(t *testing.T, root string, writer *ignoreFileLogWriter) *Runner {
	t.Helper()

	oldConfig := config.DefaultConfig
	cfg := &config.Config{Logger: gologger.DefaultLogger}
	cfg.SetConfigDir(t.TempDir())
	cfg.SetTemplatesDir(root)
	config.DefaultConfig = cfg
	t.Cleanup(func() { config.DefaultConfig = oldConfig })

	logger := &gologger.Logger{}
	logger.SetFormatter(formatter.NewCLI(false))
	logger.SetWriter(writer)
	logger.SetMaxLevel(levels.LevelWarning)

	options := types.DefaultOptions()
	options.Logger = logger
	return &Runner{options: options, Logger: logger}
}

func TestLoadIgnoreFileWarnsAndContinuesWhenActiveFileIsMissing(t *testing.T) {
	root := t.TempDir()
	writer := &ignoreFileLogWriter{}
	runner := newIgnoreFileTestRunner(t, root, writer)

	require.NoError(t, runner.loadIgnoreFile())
	require.Empty(t, runner.options.ExcludeTags)
	require.Empty(t, runner.options.ExcludedTemplates)
	require.Empty(t, writer.records)
	require.FileExists(t, config.DefaultConfig.GetIgnoreFilePath())
}

func TestLoadIgnoreFileRejectsCorruptActiveFile(t *testing.T) {
	root := t.TempDir()
	writer := &ignoreFileLogWriter{}
	runner := newIgnoreFileTestRunner(t, root, writer)
	path := config.DefaultConfig.GetIgnoreFilePath()
	require.NoError(t, os.WriteFile(path, []byte("tags: ["), 0o600))

	err := runner.loadIgnoreFile()
	require.ErrorContains(t, err, "error parsing")
	require.ErrorContains(t, err, strconv.Quote(path))
	require.Empty(t, writer.records)
}
