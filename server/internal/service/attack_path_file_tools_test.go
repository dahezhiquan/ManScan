package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestAttackPathFileToolsCommitAndReplay(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	commits := 0
	tools := newAttackPathFileTools(context.Background(), "key", strings.NewReader("/api/a\n/../../etc/passwd\n/api/b\n"), file, 3, func(_ context.Context, p, k int) error { commits++; return nil }, testAttackPathPrompts(t))
	if _, err := tools.call("finish", json.RawMessage("{}")); err == nil {
		t.Fatal("premature finish accepted")
	}
	for _, raw := range []string{`{"limit":0}`, `{"path":"../../config.yaml"}`} {
		if _, err := tools.call("read_paths", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted arguments: %s", raw)
		}
	}
	value, err := tools.call("read_paths", json.RawMessage(`{"limit":2}`))
	if err != nil {
		t.Fatal(err)
	}
	batch := value.(map[string]interface{})
	id := batch["batch_id"].(string)
	repeated, err := tools.call("read_paths", json.RawMessage(`{"limit":2000}`))
	if err != nil || repeated.(map[string]interface{})["batch_id"] != id {
		t.Fatal("pending batch changed")
	}
	bad, _ := json.Marshal(map[string]interface{}{"batch_id": id, "malicious_indexes": []int{2}})
	if _, err := tools.call("write_filtered_paths", bad); err == nil {
		t.Fatal("invalid index accepted")
	}
	args, _ := json.Marshal(map[string]interface{}{"batch_id": id, "malicious_indexes": []int{1}})
	for i := 0; i < 2; i++ {
		if _, err := tools.call("write_filtered_paths", args); err != nil {
			t.Fatal(err)
		}
	}
	if commits != 1 {
		t.Fatal("replayed commit changed progress")
	}
	value, err = tools.call("read_paths", json.RawMessage("{}"))
	if err != nil {
		t.Fatal(err)
	}
	args, _ = json.Marshal(map[string]interface{}{"batch_id": value.(map[string]interface{})["batch_id"], "malicious_indexes": []int{}})
	if _, err := tools.call("write_filtered_paths", args); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.call("finish", json.RawMessage("{}")); err != nil {
		t.Fatal(err)
	}
	p, k, done, err := tools.snapshot()
	if err != nil || p != 3 || k != 2 || !done || commits != 2 {
		t.Fatalf("snapshot: %d %d %v %v", p, k, done, err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	result, err := io.ReadAll(file)
	if err != nil || string(result) != "/api/a\n/api/b\n" {
		t.Fatalf("output=%q err=%v", result, err)
	}
}

func TestAttackPathFileToolsRejectLeaseLossAndUnauthenticatedAccess(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	tools := newAttackPathFileTools(context.Background(), "key", strings.NewReader("/api/a\n"), file, 1, func(context.Context, int, int) error { return errors.New("lease lost") }, testAttackPathPrompts(t))
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	rec := httptest.NewRecorder()
	tools.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status=%d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer key")
	req.Header.Set("Origin", "https://untrusted.example")
	rec = httptest.NewRecorder()
	tools.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("origin status=%d", rec.Code)
	}
	value, err := tools.call("read_paths", json.RawMessage("{}"))
	if err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(map[string]interface{}{"batch_id": value.(map[string]interface{})["batch_id"], "malicious_indexes": []int{}})
	if _, err := tools.call("write_filtered_paths", args); err == nil {
		t.Fatal("ignored lease loss")
	}
	if _, err := tools.call("finish", json.RawMessage("{}")); err == nil {
		t.Fatal("finalized after lease loss")
	}
}

func TestAttackPathFileToolsBoundedReadsAndEmptyOutput(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	input := strings.Repeat("/"+strings.Repeat("x", 2047)+"\n", 100)
	tools := newAttackPathFileTools(context.Background(), "key", strings.NewReader(input), file, 100, nil, testAttackPathPrompts(t))
	for {
		value, err := tools.call("read_paths", json.RawMessage(`{"limit":2000}`))
		if err != nil {
			t.Fatal(err)
		}
		result := value.(map[string]interface{})
		paths := result["paths"].([]string)
		if len(paths) == 0 {
			break
		}
		if len(paths)*2048 > attackPathToolMaxBytes {
			t.Fatal("read exceeded byte cap")
		}
		remove := make([]int, len(paths))
		for i := range paths {
			remove[i] = i
		}
		args, _ := json.Marshal(map[string]interface{}{"batch_id": result["batch_id"], "malicious_indexes": remove})
		if _, err := tools.call("write_filtered_paths", args); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tools.call("finish", json.RawMessage("{}")); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatal("all malicious paths should produce an empty file")
	}
}
