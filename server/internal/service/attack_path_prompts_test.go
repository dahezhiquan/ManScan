package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func testAttackPathPromptFile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "prompt.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "prompt.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testAttackPathPrompts(t *testing.T) attackPathPrompts {
	t.Helper()
	prompts, err := loadAttackPathPrompts(testAttackPathPromptFile(t), 3)
	if err != nil {
		t.Fatal(err)
	}
	return prompts
}

func rewriteTestAttackPathPrompts(t *testing.T, path string, edit func(map[string]string)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Prompts map[string]string `yaml:"prompts"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	edit(document.Prompts)
	data, err = yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAttackPathPromptsRequireAllIdentifiers(t *testing.T) {
	for _, id := range []string{attackPathSystemPromptID, attackPathTaskPromptID, attackPathReadPromptID, attackPathWritePromptID, attackPathFinishPromptID} {
		t.Run(id, func(t *testing.T) {
			path := testAttackPathPromptFile(t)
			rewriteTestAttackPathPrompts(t, path, func(prompts map[string]string) { delete(prompts, id) })
			if _, err := NewClaudeAttackPathProcessor("claude", "http://127.0.0.1:4000", "local-key", "test-model", path); err == nil || !strings.Contains(err.Error(), id) {
				t.Fatalf("missing prompt %s: error=%v", id, err)
			}
		})
	}
}

func TestAttackPathPromptsValidateBeforeStartingCLI(t *testing.T) {
	path := testAttackPathPromptFile(t)
	processor, err := NewClaudeAttackPathProcessor(filepath.Join(t.TempDir(), "no-cli"), "http://127.0.0.1:4000", "local-key", "test-model", path)
	if err != nil {
		t.Fatal(err)
	}
	rewriteTestAttackPathPrompts(t, path, func(prompts map[string]string) { prompts[attackPathTaskPromptID] = "{{unknown}}" })
	_, _, err = processor.Process(context.Background(), strings.NewReader("/api/a\n"), nil, 1, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("Process should reject changed invalid prompts before starting CLI: %v", err)
	}
}
