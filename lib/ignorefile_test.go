package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"ManScan/pkg/catalog/config"
	"github.com/stretchr/testify/require"
)

func TestNewNucleiEngineUsesConfigIgnoreFileInsteadOfTemplateRootIgnore(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, config.NucleiIgnoreFileName)
	require.NoError(t, os.WriteFile(path, []byte("tags: ["), 0o600))

	cfg := config.DefaultConfig
	oldRoot := cfg.TemplatesDirectory
	oldConfigDir := cfg.GetConfigDir()
	t.Cleanup(func() {
		cfg.SetTemplatesDir(oldRoot)
		cfg.SetConfigDir(oldConfigDir)
	})
	cfg.SetConfigDir(t.TempDir())
	cfg.SetTemplatesDir(root)

	engine, err := NewNucleiEngineCtx(context.Background())
	require.NoError(t, err)
	require.NotNil(t, engine)
	engine.Close()
}
