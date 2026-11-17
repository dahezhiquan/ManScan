package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAttackPathCostAIForce is opt-in and records real usage without logging paths or credentials.
func TestAttackPathCostAIForce(t *testing.T) {
	if os.Getenv("MANSCAN_TEST_ATTACK_PATH_COST") != "1" {
		t.Skip("real cost measurement is opt-in")
	}
	started := time.Now()
	cfg, gateway := configuredAttackPathTestGateway(t)
	dir := os.Getenv("MANSCAN_TEST_ATTACK_PATH_COST_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("measurement directory must be absolute")
	}
	source, err := os.Open(filepath.Join(dir, "paths.txt"))
	if err != nil {
		t.Fatal("cannot open measurement input")
	}
	defer source.Close()
	prepStart := time.Now()
	total, err := writeUniqueAttackPaths(context.Background(), filepath.Join(dir, "input.txt"), source)
	if err != nil {
		t.Fatal("cannot prepare unique paths")
	}
	prepSeconds := time.Since(prepStart).Seconds()
	input, err := os.Open(filepath.Join(dir, "input.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(filepath.Join(dir, "kept.txt"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	usageFile, err := os.OpenFile(filepath.Join(dir, "requests.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer usageFile.Close()
	var recordMu sync.Mutex
	var recordErr error
	record := func(value map[string]interface{}) {
		recordMu.Lock()
		defer recordMu.Unlock()
		if recordErr == nil {
			recordErr = json.NewEncoder(usageFile).Encode(value)
		}
	}
	var calls, active, peak atomic.Int32
	transport := http.DefaultTransport
	gateway.client.Transport = gatewayTransport(func(req *http.Request) (*http.Response, error) {
		number := calls.Add(1)
		current := active.Add(1)
		for old := peak.Load(); current > old; old = peak.Load() {
			if peak.CompareAndSwap(old, current) {
				break
			}
		}
		begin := time.Now()
		response, err := transport.RoundTrip(req)
		if err != nil {
			active.Add(-1)
			record(map[string]interface{}{"request": number, "seconds": time.Since(begin).Seconds(), "transport_error": true, "usage_present": false})
			return nil, err
		}
		response.Body = &attackPathCostBody{ReadCloser: response.Body, done: func(data []byte, complete bool) {
			active.Add(-1)
			item := map[string]interface{}{"request": number, "status": response.StatusCode, "seconds": time.Since(begin).Seconds(), "body_complete": complete, "usage_present": false}
			var envelope struct {
				Usage map[string]interface{} `json:"usage"`
				Code  int                    `json:"code"`
			}
			if complete && json.Unmarshal(data, &envelope) == nil {
				item["code"] = envelope.Code
				if len(envelope.Usage) > 0 {
					item["usage_present"] = true
					item["usage"] = attackPathCostNumericUsage(envelope.Usage)
				}
			}
			record(item)
			t.Logf("upstream request=%d status=%d elapsed=%s usage=%v", number, response.StatusCode, time.Since(begin).Round(time.Millisecond), item["usage_present"])
		}}
		return response, nil
	})
	limiter := NewAPIKeyRateLimiter(NewThirdPartyAPIKeyService(gateway.repo, gateway.box))
	classifier := NewAIForceAttackPathClassifier(gateway, limiter, cfg.AI.AttackPathConcurrency)
	var modelFirst atomic.Int64
	var batches, modelRemoved atomic.Int32
	observed := attackPathBatchClassifierFunc(func(ctx context.Context, system string, paths []string) ([]int, error) {
		modelFirst.CompareAndSwap(0, time.Now().UnixNano())
		number := batches.Add(1)
		begin := time.Now()
		result, err := classifier.Classify(ctx, system, paths)
		if err == nil {
			modelRemoved.Add(int32(len(result)))
		}
		t.Logf("batch=%d paths=%d removed=%d elapsed=%s success=%v", number, len(paths), len(result), time.Since(begin).Round(time.Millisecond), err == nil)
		return result, err
	})
	initStart := time.Now()
	processor, err := NewHybridAttackPathProcessor(observed, cfg.PromptFilePath(), cfg.AI.AttackPathConcurrency, cfg.AI.AttackPathBatchSize)
	if err != nil {
		t.Fatal(err)
	}
	initSeconds := time.Since(initStart).Seconds()
	hybrid := processor.(*hybridAttackPathProcessor)
	tracked := &attackPathCostRules{rules: hybrid.rules, decisions: map[string]attackPathDecision{}, t: t}
	hybrid.rules = tracked
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	processingStart := time.Now()
	last := 0
	processed, kept, processErr := processor.Process(ctx, input, output, total, func(_ context.Context, p, k int) error {
		if p <= last || p > total || k > p {
			return errors.New("invalid measured progress")
		}
		last = p
		return nil
	})
	processSeconds := time.Since(processingStart).Seconds()
	if err := output.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := usageFile.Sync(); err != nil {
		t.Fatal(err)
	}
	recordMu.Lock()
	usageErr := recordErr
	recordMu.Unlock()
	if usageErr != nil {
		t.Fatal("cannot persist usage records")
	}
	localSeconds := processSeconds
	modelSeconds := 0.0
	if first := modelFirst.Load(); first > 0 {
		localSeconds = time.Unix(0, first).Sub(processingStart).Seconds()
		modelSeconds = processSeconds - localSeconds
	}
	stats := map[string]interface{}{"model": cfg.AI.Model, "concurrency": cfg.AI.AttackPathConcurrency, "batch_size": cfg.AI.AttackPathBatchSize, "total": total, "processed": processed, "kept": kept, "local_keep": tracked.counts[attackPathNormal], "local_drop": tracked.counts[attackPathMalicious], "model_review": tracked.counts[attackPathUncertain], "model_drop": modelRemoved.Load(), "logical_batches": batches.Load(), "http_requests": calls.Load(), "http_peak": peak.Load(), "dedup_seconds": prepSeconds, "engine_init_seconds": initSeconds, "processing_seconds": processSeconds, "local_stage_seconds": localSeconds, "model_and_merge_seconds": modelSeconds, "success": processErr == nil, "wall_seconds": time.Since(started).Seconds()}
	if processErr != nil {
		stats["error"] = processErr.Error()
	}
	encoded, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("measurement %s", encoded)
	if processErr != nil {
		t.Fatal(processErr)
	}
	if processed != total || last != total || active.Load() != 0 {
		t.Fatal("incomplete processing")
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	keptPaths := map[string]bool{}
	scan := bufio.NewScanner(output)
	scan.Buffer(make([]byte, 4096), 4096)
	for scan.Scan() {
		if keptPaths[scan.Text()] {
			t.Fatal("duplicate output")
		}
		keptPaths[scan.Text()] = true
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if len(keptPaths) != kept {
		t.Fatal("output count mismatch")
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	decisions, err := os.OpenFile(filepath.Join(dir, "decisions.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer decisions.Close()
	excluded, err := os.OpenFile(filepath.Join(dir, "excluded.txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer excluded.Close()
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	ordered := bufio.NewScanner(output)
	ordered.Buffer(make([]byte, 4096), 4096)
	scan = bufio.NewScanner(input)
	scan.Buffer(make([]byte, 4096), 4096)
	for scan.Scan() {
		path := scan.Text()
		decision, ok := tracked.decisions[path]
		if !ok {
			t.Fatal("missing local decision")
		}
		keep := keptPaths[path]
		stage := "local"
		if decision == attackPathUncertain {
			stage = "model"
		}
		if err := json.NewEncoder(decisions).Encode(map[string]interface{}{"path": path, "stage": stage, "kept": keep}); err != nil {
			t.Fatal(err)
		}
		if keep {
			if !ordered.Scan() || ordered.Text() != path {
				t.Fatal("output order mismatch")
			}
		} else {
			if _, err := excluded.WriteString(path + "\n"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if ordered.Scan() {
		t.Fatal("extra output")
	}
	if err := ordered.Err(); err != nil {
		t.Fatal(err)
	}
	if err := decisions.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := excluded.Sync(); err != nil {
		t.Fatal(err)
	}
}

type attackPathCostRules struct {
	rules     attackPathLocalClassifier
	mu        sync.Mutex
	counts    [3]int
	decisions map[string]attackPathDecision
	t         *testing.T
}

func (r *attackPathCostRules) classify(ctx context.Context, raw string) (attackPathDecision, error) {
	d, err := r.rules.classify(ctx, raw)
	if err != nil {
		return d, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[d]++
	r.decisions[raw] = d
	if n := len(r.decisions); n%5000 == 0 {
		r.t.Logf("local scanned=%d keep=%d drop=%d review=%d", n, r.counts[attackPathNormal], r.counts[attackPathMalicious], r.counts[attackPathUncertain])
	}
	return d, nil
}

type attackPathCostBody struct {
	io.ReadCloser
	buffer   bytes.Buffer
	overflow bool
	eof      bool
	once     sync.Once
	done     func([]byte, bool)
}

func (b *attackPathCostBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if !b.overflow {
		if b.buffer.Len()+n > 4<<20 {
			b.overflow = true
			b.buffer.Reset()
		} else {
			b.buffer.Write(p[:n])
		}
	}
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}
func (b *attackPathCostBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { b.done(b.buffer.Bytes(), b.eof && !b.overflow) })
	return err
}

// Retain numeric usage fields only; upstream message content is never persisted here.
func attackPathCostNumericUsage(value map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for key, item := range value {
		switch v := item.(type) {
		case float64:
			out[key] = v
		case map[string]interface{}:
			out[key] = attackPathCostNumericUsage(v)
		}
	}
	return out
}

// Verify the observer preserves response bytes and records a response only once.
func TestAttackPathCostObserver(t *testing.T) {
	for _, tc := range []struct {
		name     string
		data     []byte
		complete bool
	}{
		{"small", []byte("{\"usage\":{\"prompt_tokens\":123}}"), true},
		{"oversized", bytes.Repeat([]byte("x"), (4<<20)+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			body := &attackPathCostBody{ReadCloser: io.NopCloser(bytes.NewReader(tc.data)), done: func(data []byte, complete bool) {
				calls++
				if complete != tc.complete {
					t.Errorf("complete=%v", complete)
				}
				if complete && !bytes.Equal(data, tc.data) {
					t.Error("captured response changed")
				}
				if !complete && len(data) != 0 {
					t.Error("oversized response retained")
				}
			}}
			got, err := io.ReadAll(body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Fatal("observer changed response")
			}
			for i := 0; i < 2; i++ {
				if err := body.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if calls != 1 {
				t.Fatalf("response counted %d times", calls)
			}
		})
	}
	input := map[string]interface{}{"prompt_tokens": float64(123), "output_tokens": float64(4), "details": map[string]interface{}{"cached_tokens": float64(0), "text": "private content"}, "text": "private content"}
	clean := attackPathCostNumericUsage(input)
	data, err := json.Marshal(clean)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("private content")) {
		t.Fatal("usage observer retained nonnumeric data")
	}
	if clean["prompt_tokens"] != float64(123) || clean["output_tokens"] != float64(4) {
		t.Fatal("usage counters changed")
	}
}
