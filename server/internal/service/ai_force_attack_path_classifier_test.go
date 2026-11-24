package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/secretbox"
)

func testBatchGateway(t *testing.T) *AIForceClaudeGateway {
	t.Helper()
	box, err := secretbox.New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := box.Encrypt("test-upstream-key")
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewAIForceClaudeGateway("test-model", "tester", "local-key", aiForceKeyRepo{&entity.ThirdPartyAPIKey{ID: 1, PlatformURL: "https://ai-force.duxiaoman-int.com/", Description: "原力平台", EncryptedKey: encrypted}}, box)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func batchCompletionResponse(t *testing.T, arguments, reason string) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{"choices": []interface{}{map[string]interface{}{
		"finish_reason": reason,
		"message": map[string]interface{}{"tool_calls": []interface{}{map[string]interface{}{
			"id": "call_classify", "type": "function", "function": map[string]string{"name": "classify_paths", "arguments": arguments},
		}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}
}

type batchRateLimiter struct {
	calls atomic.Int32
	err   error
}

func (l *batchRateLimiter) Wait(ctx context.Context, id int64) error {
	l.calls.Add(1)
	if id != 1 {
		return errors.New("wrong key")
	}
	return l.err
}

func TestAIForceBatchClassification(t *testing.T) {
	g := testBatchGateway(t)
	limiter := &batchRateLimiter{}
	g.client = &http.Client{Transport: gatewayTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != aiForceHost || r.Header.Get("Authorization") != "Bearer test-upstream-key" {
			t.Error("incorrect upstream authentication")
		}
		var payload struct {
			Messages   []struct{ Role, Content string }         `json:"messages"`
			ToolChoice struct{ Function struct{ Name string } } `json:"tool_choice"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return nil, err
		}
		if len(payload.Messages) != 2 || !strings.Contains(payload.Messages[0].Content, "configured criteria") || payload.ToolChoice.Function.Name != "classify_paths" {
			return nil, errors.New("classification is not an independent forced-tool request")
		}
		var input struct {
			Paths []indexedAttackPath
			Count int
		}
		if err := json.Unmarshal([]byte(payload.Messages[1].Content), &input); err != nil {
			return nil, err
		}
		if input.Count != 2 || len(input.Paths) != 2 || input.Paths[0].Index != 0 || input.Paths[0].Path != "/api/users" || input.Paths[1].Index != 1 || input.Paths[1].Path != "/../../etc/passwd" {
			return nil, errors.New("classification input lacks explicit positional indexes")
		}
		return batchCompletionResponse(t, `{"processed":2,"malicious_indexes":[1]}`, "tool_calls"), nil
	})}
	classifier := NewAIForceAttackPathClassifier(g, limiter, 5)
	result, err := classifier.Classify(context.Background(), "configured criteria", []string{"/api/users", "/../../etc/passwd"})
	if err != nil || len(result) != 1 || result[0] != 1 || limiter.calls.Load() != 1 {
		t.Fatalf("result=%v err=%v limits=%d", result, err, limiter.calls.Load())
	}
}

func TestAIForceBatchRejectsIncompleteResults(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"processed":2}`, `{"processed":1,"malicious_indexes":[]}`,
		`{"processed":2,"malicious_indexes":null}`, `{"processed":2,"malicious_indexes":[2]}`,
		`{"processed":2,"malicious_indexes":[-1]}`, `{"processed":2,"malicious_indexes":[1,1]}`,
		`{"processed":2,"malicious_indexes":[],"extra":"ignored"}`,
		`{"processed":2,"malicious_indexes":[]} {}`,
	} {
		t.Run(raw, func(t *testing.T) {
			g := testBatchGateway(t)
			var calls atomic.Int32
			g.client = &http.Client{Transport: gatewayTransport(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return batchCompletionResponse(t, raw, "tool_calls"), nil
			})}
			_, err := NewAIForceAttackPathClassifier(g, nil, 5).Classify(context.Background(), "criteria", []string{"/a", "/b"})
			if err == nil || calls.Load() != 3 {
				t.Fatalf("invalid result budget: err=%v calls=%d", err, calls.Load())
			}
		})
	}
	g := testBatchGateway(t)
	g.client = &http.Client{Transport: gatewayTransport(func(*http.Request) (*http.Response, error) {
		return batchCompletionResponse(t, `{"processed":2,"malicious_indexes":[]}`, "length"), nil
	})}
	if _, err := NewAIForceAttackPathClassifier(g, nil, 5).Classify(context.Background(), "criteria", []string{"/a", "/b"}); err == nil {
		t.Fatal("accepted truncated model output")
	}
}

func TestAIForceBatchRetriesInvalidResult(t *testing.T) {
	g := testBatchGateway(t)
	var calls atomic.Int32
	g.client = &http.Client{Transport: gatewayTransport(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return batchCompletionResponse(t, `{"processed":2,"malicious_indexes":[2]}`, "tool_calls"), nil
		}
		return batchCompletionResponse(t, `{"processed":2,"malicious_indexes":[1]}`, "tool_calls"), nil
	})}
	result, err := NewAIForceAttackPathClassifier(g, nil, 5).Classify(context.Background(), "criteria", []string{"/a", "/b"})
	if err != nil || len(result) != 1 || result[0] != 1 || calls.Load() != 2 {
		t.Fatalf("format retry failed: result=%v err=%v calls=%d", result, err, calls.Load())
	}
}

func TestAIForceBatchRetriesAndCancellation(t *testing.T) {
	g := testBatchGateway(t)
	var calls atomic.Int32
	g.client = &http.Client{Transport: gatewayTransport(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"1"}}, Body: io.NopCloser(strings.NewReader("private upstream error"))}, nil
		}
		return batchCompletionResponse(t, `{"processed":1,"malicious_indexes":[]}`, "tool_calls"), nil
	})}
	start := time.Now()
	result, err := NewAIForceAttackPathClassifier(g, nil, 5).Classify(context.Background(), "criteria", []string{"/a"})
	if err != nil || result == nil || calls.Load() != 2 || time.Since(start) < time.Second {
		t.Fatalf("retry failed: %v calls=%d", err, calls.Load())
	}
	g.client = &http.Client{Transport: gatewayTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"60"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := NewAIForceAttackPathClassifier(g, nil, 5).Classify(ctx, "criteria", []string{"/a"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retry ignored cancellation: %v", err)
	}
}

func TestAIForceBatchHonorsKeyRateLimit(t *testing.T) {
	g := testBatchGateway(t)
	g.client = &http.Client{Transport: gatewayTransport(func(*http.Request) (*http.Response, error) {
		t.Error("request sent despite limiter rejection")
		return nil, errors.New("unexpected")
	})}
	limiter := &batchRateLimiter{err: context.Canceled}
	if _, err := NewAIForceAttackPathClassifier(g, limiter, 5).Classify(context.Background(), "criteria", []string{"/a"}); err == nil {
		t.Fatal("ignored limiter")
	}
}

func TestAIForceBatchBusinessConcurrencyLimit(t *testing.T) {
	g := testBatchGateway(t)
	var active, rejections atomic.Int32
	g.client = &http.Client{Transport: gatewayTransport(func(*http.Request) (*http.Response, error) {
		current := active.Add(1)
		defer active.Add(-1)
		if current > 1 {
			rejections.Add(1)
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":110602,"message":"private provider error"}`))}, nil
		}
		time.Sleep(40 * time.Millisecond)
		return batchCompletionResponse(t, `{"processed":1,"malicious_indexes":[]}`, "tool_calls"), nil
	})}
	classifier := NewAIForceAttackPathClassifier(g, nil, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := classifier.Classify(ctx, "criteria", []string{"/a"}); err != nil {
				t.Errorf("did not recover from provider limit: %v", err)
			}
		}()
	}
	workers.Wait()
	c := classifier.(*aiForceAttackPathClassifier)
	c.mu.Lock()
	defer c.mu.Unlock()
	if rejections.Load() == 0 || c.limit != 1 || c.active != 0 {
		t.Fatalf("adaptive gate not applied: rejections=%d limit=%d active=%d", rejections.Load(), c.limit, c.active)
	}
}

func TestAIForceBatchSharedFiveRequestLimit(t *testing.T) {
	g := testBatchGateway(t)
	var active, peak atomic.Int32
	entered := make(chan struct{}, 12)
	release := make(chan struct{})
	g.client = &http.Client{Transport: gatewayTransport(func(r *http.Request) (*http.Response, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return batchCompletionResponse(t, `{"processed":1,"malicious_indexes":[]}`, "tool_calls"), nil
	})}
	classifier := NewAIForceAttackPathClassifier(g, nil, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	// Several callers/tasks share this single classifier and key budget.
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := classifier.Classify(ctx, "criteria", []string{"/a"}); err != nil {
				t.Errorf("classification failed: %v", err)
			}
		}()
	}
	for i := 0; i < 5; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			close(release)
			wg.Wait()
			t.Fatal("five requests did not overlap")
		}
	}
	select {
	case <-entered:
		t.Error("a sixth request bypassed the shared gate")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if peak.Load() != 5 || active.Load() != 0 {
		t.Fatalf("peak=%d active=%d", peak.Load(), active.Load())
	}
}

func TestAIForceBatchSplitsMalformedLargeResult(t *testing.T) {
	for _, mode := range []string{"recover", "invalid_leaf", "transport", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			g := testBatchGateway(t)
			var calls atomic.Int32
			g.client = &http.Client{Transport: gatewayTransport(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				if mode == "transport" {
					return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
				}
				var payload struct{ Messages []struct{ Content string } }
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					return nil, err
				}
				var batch struct {
					Paths []indexedAttackPath
					Count int
				}
				if err := json.Unmarshal([]byte(payload.Messages[1].Content), &batch); err != nil {
					return nil, err
				}
				if batch.Count > 64 && mode == "timeout" {
					return nil, context.DeadlineExceeded
				}
				if batch.Count > 64 || mode == "invalid_leaf" {
					return batchCompletionResponse(t, `{"processed":0,"malicious_indexes":[]}`, "tool_calls"), nil
				}
				indexes := []int{}
				for _, path := range batch.Paths {
					if path.Path == "/review/3" || path.Path == "/review/78" {
						indexes = append(indexes, path.Index)
					}
				}
				args, err := json.Marshal(map[string]interface{}{"processed": batch.Count, "malicious_indexes": indexes})
				if err != nil {
					return nil, err
				}
				return batchCompletionResponse(t, string(args), "tool_calls"), nil
			})}
			paths := make([]string, 100)
			for i := range paths {
				paths[i] = fmt.Sprintf("/review/%d", i)
			}
			result, err := NewAIForceAttackPathClassifier(g, nil, 5).Classify(context.Background(), "criteria", paths)
			switch mode {
			case "recover", "timeout":
				wantCalls := int32(5)
				if mode == "timeout" {
					wantCalls = 3
				}
				if err != nil || len(result) != 2 || result[0] != 3 || result[1] != 78 || calls.Load() != wantCalls {
					t.Fatalf("result=%v err=%v calls=%d", result, err, calls.Load())
				}
			case "invalid_leaf":
				if err == nil || calls.Load() != 6 {
					t.Fatalf("unbounded or accepted invalid results: err=%v calls=%d", err, calls.Load())
				}
			case "transport":
				if err == nil || calls.Load() != 1 {
					t.Fatalf("split non-format failure: err=%v calls=%d", err, calls.Load())
				}
			}
		})
	}
}
