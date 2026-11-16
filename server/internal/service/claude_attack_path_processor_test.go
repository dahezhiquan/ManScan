package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/secretbox"
)

func TestClaudeAttackPathProcessorRequiresSafeGateway(t *testing.T) {
	for _, base := range []string{"http://adapter.example.test", "%", "https://user:pass@example.test", "https://example.test/?key=secret"} {
		if _, err := NewClaudeAttackPathProcessor("claude", base, "test-key", "claude-test", testAttackPathPromptFile(t)); err == nil {
			t.Fatalf("accepted unsafe URL: %s", base)
		}
	}
	if _, err := NewClaudeAttackPathProcessor("claude", "http://127.0.0.1:4000", "test-key", "claude-test", testAttackPathPromptFile(t)); err != nil {
		t.Fatal("rejected loopback gateway")
	}
}

func TestClaudeAttackPathProcessorRejectsClaimedSuccessWithoutFile(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "claude")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s' '{\"type\":\"result\",\"is_error\":false}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	processor, err := NewClaudeAttackPathProcessor(binary, "http://127.0.0.1:4000", "test-key", "claude-test", testAttackPathPromptFile(t))
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if _, _, err := processor.Process(context.Background(), strings.NewReader("/api/ok\n"), output, 1, nil); err == nil {
		t.Fatal("accepted model prose without file completion")
	}
}

// Real CLI, local MCP, and protocol adapter; the upstream model is deterministic and local.
func TestClaudeAttackPathProcessorRealCLI(t *testing.T) {
	binary, err := exec.LookPath("claude")
	if err != nil {
		t.Skip("Claude CLI not installed")
	}
	box, err := secretbox.New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := box.Encrypt("mock-key")
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewAIForceClaudeGateway("https://ai-force.duxiaoman-int.com/agent-api/openai", "claude-sonnet-4-5", "tester", "local-secret", aiForceKeyRepo{&entity.ThirdPartyAPIKey{PlatformURL: "https://ai-force.duxiaoman-int.com/", EncryptedKey: encrypted}}, box)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	promptFile := testAttackPathPromptFile(t)
	var expectedPrompts attackPathPrompts
	gateway.client = &http.Client{Transport: gatewayTransport(func(req *http.Request) (*http.Response, error) {
		requestNumber := requests.Add(1)
		var payload struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Tools []struct {
				Function struct {
					Name        string `json:"name"`
					Description string `json:"description"`
				} `json:"function"`
			} `json:"tools"`
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			return nil, err
		}
		if len(payload.Tools) != 3 {
			t.Errorf("expected exactly 3 scoped tools, got %d", len(payload.Tools))
		}
		foundSystem, foundTask := false, false
		for _, message := range payload.Messages {
			foundSystem = foundSystem || (message.Role == "system" && strings.Contains(message.Content, expectedPrompts.system))
			foundTask = foundTask || (message.Role == "user" && strings.Contains(message.Content, expectedPrompts.task))
		}
		if !foundSystem || !foundTask {
			t.Errorf("CLI did not receive the reloaded system/task prompt snapshot: system=%v task=%v", foundSystem, foundTask)
		}
		// CLI may normalize full-width punctuation in MCP tool descriptions.
		punctuation := strings.NewReplacer("，", ",", "；", ";")
		for _, tool := range payload.Tools {
			for name, description := range map[string]string{"read_paths": expectedPrompts.readPaths, "write_filtered_paths": expectedPrompts.writeFilteredPaths, "finish": expectedPrompts.finish} {
				if strings.HasSuffix(tool.Function.Name, "__"+name) && punctuation.Replace(tool.Function.Description) != punctuation.Replace(description) {
					t.Errorf("CLI tool description %s differs: got=%q want=%q", name, tool.Function.Description, description)
				}
			}
		}
		// A concurrent edit must not change any prompt in the running session.
		if requestNumber == 1 {
			if err := os.WriteFile(promptFile, []byte("prompts: {}\n"), 0600); err != nil {
				return nil, err
			}
		}
		name := "read_paths"
		args := map[string]interface{}{"limit": 2000}
		done := false
		last := payload.Messages[len(payload.Messages)-1]
		if last.Role == "tool" {
			var result struct {
				BatchID   string   `json:"batch_id"`
				Paths     []string `json:"paths"`
				Processed int      `json:"processed"`
				Total     int      `json:"total"`
				Finished  bool     `json:"finished"`
			}
			if err := json.Unmarshal([]byte(last.Content), &result); err != nil {
				t.Errorf("invalid tool result: %s", last.Content)
				return nil, err
			}
			if result.Finished {
				done = true
			} else if len(result.Paths) > 0 {
				name = "write_filtered_paths"
				indices := []int{}
				for i, path := range result.Paths {
					if strings.Contains(path, "../") {
						indices = append(indices, i)
					}
				}
				args = map[string]interface{}{"batch_id": result.BatchID, "malicious_indexes": indices}
			} else if result.Processed == result.Total {
				name = "finish"
				args = map[string]interface{}{}
			}
		}
		message := map[string]interface{}{"role": "assistant", "content": "Finished"}
		stop := "stop"
		if !done {
			fullName := ""
			for _, tool := range payload.Tools {
				if strings.HasSuffix(tool.Function.Name, "__"+name) {
					fullName = tool.Function.Name
				}
			}
			if fullName == "" {
				t.Errorf("missing tool %s", name)
			}
			encoded, _ := json.Marshal(args)
			message = map[string]interface{}{"role": "assistant", "content": nil, "tool_calls": []map[string]interface{}{{"id": "call_" + name + newGatewayRequestID(), "type": "function", "function": map[string]interface{}{"name": fullName, "arguments": string(encoded)}}}}
			stop = "tool_calls"
		}
		body, _ := json.Marshal(map[string]interface{}{"id": "msg_test", "choices": []map[string]interface{}{{"message": message, "finish_reason": stop}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 50}})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})}
	server := httptest.NewServer(gateway)
	defer server.Close()
	processor, err := NewClaudeAttackPathProcessor(binary, server.URL, "local-secret", "claude-sonnet-4-5", promptFile)
	if err != nil {
		t.Fatal(err)
	}
	// Edits after construction must be picked up before the task starts.
	rewriteTestAttackPathPrompts(t, promptFile, func(prompts map[string]string) {
		for id, value := range prompts {
			prompts[id] = value + " YAML revision two."
		}
	})
	expectedPrompts, err = loadAttackPathPrompts(promptFile, 2100)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var input, expected strings.Builder
	for i := 0; i < 2100; i++ {
		if i == 2050 {
			input.WriteString("/../../etc/passwd\n")
			continue
		}
		path := fmt.Sprintf("/api/items/%d\n", i)
		input.WriteString(path)
		expected.WriteString(path)
	}
	var progress, commits int
	processed, kept, err := processor.Process(ctx, strings.NewReader(input.String()), output, 2100, func(_ context.Context, p, k int) error { progress = p; commits++; return nil })
	if err != nil {
		t.Fatalf("Process: %v (upstream requests=%d)", err, requests.Load())
	}
	actual, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	if processed != 2100 || kept != 2099 || progress != 2100 || commits != 2 || string(actual) != expected.String() || requests.Load() != 6 {
		t.Fatalf("processed=%d kept=%d progress=%d requests=%d output=%q", processed, kept, progress, requests.Load(), actual)
	}
}
