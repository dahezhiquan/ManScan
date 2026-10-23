package config

import (
	"strings"
	"testing"
)

func TestAPIKeyEncryptionConfiguration(t *testing.T) {
	for _, key := range []string{"", "short", strings.Repeat(" ", 32), strings.Repeat("x", 31)} {
		if err := (AuthConfig{APIKeyEncryptionKey: key}).ValidateAPIKeyEncryptionKey(); err == nil {
			t.Fatal("accepted an empty or short API Key encryption secret")
		}
	}
	fileKey := strings.Repeat("a", 32)
	cfg := AuthConfig{APIKeyEncryptionKey: fileKey}
	if err := cfg.ValidateAPIKeyEncryptionKey(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MANSCAN_API_KEY_ENCRYPTION_KEY", "")
	cfg.ApplyEnv()
	if cfg.APIKeyEncryptionKey != fileKey {
		t.Fatal("empty environment variable must preserve file configuration")
	}
	envKey := strings.Repeat("b", 32)
	t.Setenv("MANSCAN_API_KEY_ENCRYPTION_KEY", envKey)
	cfg.ApplyEnv()
	if cfg.APIKeyEncryptionKey != envKey {
		t.Fatal("environment variable must override file configuration")
	}
}
