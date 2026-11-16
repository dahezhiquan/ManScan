package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPromptFilePath(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"", "config.yaml", "deployment/config.yaml", filepath.Join(root, "external/config.yaml")} {
		cfg := Config{RootDir: root, ConfigFile: name}
		want := filepath.Join(root, "prompt.yaml")
		if name == "deployment/config.yaml" {
			want = filepath.Join(root, "deployment/prompt.yaml")
		} else if filepath.IsAbs(name) {
			want = filepath.Join(filepath.Dir(name), "prompt.yaml")
		}
		if got := cfg.PromptFilePath(); got != want {
			t.Fatalf("config=%q path=%q want=%q", name, got, want)
		}
	}
}

func TestPromptCatalogValidation(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"empty", ""},
		{"missing prompts", "prompts: {}"},
		{"invalid YAML", "prompts: ["},
		{"duplicate identifier", "prompts:\n  same: first\n  same: second\n"},
		{"blank identifier", "prompts:\n  ' ': value"},
		{"blank prompt", "prompts:\n  task: ' '"},
		{"numeric prompt", "prompts:\n  task: 123"},
		{"unknown top field", "prompt: value"},
		{"multiple documents", "prompts:\n  task: ok\n---\nprompts:\n  task: other"},
		{"NUL", "prompts:\n  task: \"\\0\""},
		{"long prompt", "prompts:\n  task: " + strings.Repeat("x", maxPromptBytes+1)},
		{"long file", strings.Repeat("#", maxPromptFileBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "prompt.yaml")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPromptCatalog(path); err == nil {
				t.Fatal("invalid prompt catalog was accepted")
			}
		})
	}
	if _, err := LoadPromptCatalog(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing prompt file was accepted")
	}
}

func TestPromptCatalogRenderAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prompt.yaml")
	content := "prompts:\n  task: '处理 {{ total }} 条，进度 100%，{{value}}'\n  unknown: '{{typo}}'\n  unclosed: '{{total'\n  unexpected: 'total}}'\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := LoadPromptCatalog(path)
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"total": "42", "value": "{{literal}}"}
	got, err := first.Render("task", vars)
	if err != nil || got != "处理 42 条，进度 100%，{{literal}}" {
		t.Fatalf("render=%q err=%v", got, err)
	}
	for _, id := range []string{"missing", "unknown", "unclosed", "unexpected"} {
		if _, err := first.Render(id, vars); err == nil {
			t.Fatalf("invalid identifier or placeholder accepted: %s", id)
		}
	}
	if err := os.WriteFile(path, []byte("prompts:\n  task: '更新 {{total}}'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := LoadPromptCatalog(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err = second.Render("task", vars)
	if err != nil || got != "更新 42" {
		t.Fatalf("reloaded=%q err=%v", got, err)
	}
	got, err = first.Render("task", vars)
	if err != nil || got != "处理 42 条，进度 100%，{{literal}}" {
		t.Fatalf("running snapshot changed: %q err=%v", got, err)
	}
}
