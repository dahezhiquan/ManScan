package assetdomainfingerprint

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheLookupAndHTTPProbeFailed(t *testing.T) {
	httpAlive := false
	cache := FromEntries([]Entry{
		{
			Target:    "https://app.example.com/login",
			Domain:    "app.example.com:443",
			HTTPAlive: &httpAlive,
			Components: []Component{
				{Domain: "app.example.com:443", AppName: "nginx:1.24.0", AppVersion: "1.24.0"},
				{Domain: "app.example.com:443", AppName: "nginx:1.24.0", AppVersion: "1.24.0"},
			},
		},
	})

	state, ok := cache.Lookup("app.example.com:443")
	require.True(t, ok)
	require.Len(t, state.Components, 1)
	require.True(t, cache.HTTPProbeFailed("https://app.example.com/login"))
	require.True(t, cache.HTTPProbeFailed("app.example.com:443"))
	require.False(t, cache.HTTPProbeFailed("missing.example.com:443"))
}

func TestLoadFromEnv(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "fingerprints.json")
	require.NoError(t, os.WriteFile(cachePath, []byte(`[
		{"target":"mysql.example.com:3306","http_alive":false,"components":[]}
	]`), 0o600))
	t.Setenv(CacheEnv, cachePath)

	cache := LoadFromEnv()
	require.NotNil(t, cache)
	require.True(t, cache.HTTPProbeFailed("mysql.example.com:3306"))
}
