package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/stretchr/testify/require"
)

func TestReadIgnoreFileRepairsMissingConfigIgnoreFromTemplatesDir(t *testing.T) {
	configDir := t.TempDir()
	templatesDir := t.TempDir()
	templateIgnorePath := filepath.Join(templatesDir, NucleiIgnoreFileName)
	templateIgnoreData := []byte("tags:\n  - copied-tag\nfiles:\n  - copied-file.yaml\n")
	require.NoError(t, os.WriteFile(templateIgnorePath, templateIgnoreData, 0600))

	oldConfig := DefaultConfig
	DefaultConfig = &Config{
		TemplatesDirectory: templatesDir,
		configDir:          configDir,
		Logger:             gologger.DefaultLogger,
	}
	DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() {
		DefaultConfig = oldConfig
	})

	ignorePath := DefaultConfig.GetIgnoreFilePath()
	require.NoFileExists(t, ignorePath)

	ignore, err := ReadIgnoreFile()
	require.NoError(t, err)

	require.Equal(t, []string{"copied-tag"}, ignore.Tags)
	require.Equal(t, []string{"copied-file.yaml"}, ignore.Files)
	require.FileExists(t, ignorePath)

	configIgnoreData, err := os.ReadFile(ignorePath)
	require.NoError(t, err)
	require.Equal(t, string(templateIgnoreData), string(configIgnoreData))
}

func TestReadIgnoreFileCreatesDefaultConfigIgnoreWhenTemplateIgnoreMissing(t *testing.T) {
	oldConfig := DefaultConfig
	DefaultConfig = &Config{
		TemplatesDirectory: t.TempDir(),
		configDir:          t.TempDir(),
		Logger:             gologger.DefaultLogger,
	}
	t.Cleanup(func() {
		DefaultConfig = oldConfig
	})

	ignore, err := ReadIgnoreFile()
	require.NoError(t, err)
	require.Empty(t, ignore.Tags)
	require.Empty(t, ignore.Files)
	require.FileExists(t, DefaultConfig.GetIgnoreFilePath())
}
