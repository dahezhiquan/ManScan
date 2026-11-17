package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Explicitly opt in; optional input reuses an uploaded sample against the same provider.
func TestHybridAttackPathProcessorAIForce(t *testing.T) {
	cfg, gateway := configuredAttackPathTestGateway(t)
	input := "/api/users\n/../../etc/passwd\n/api/orders\n"
	path := os.Getenv("MANSCAN_TEST_ATTACK_PATH_INPUT")
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal("cannot open integration input")
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil || len(data) > 1<<20 {
			t.Fatal("integration sample must be at most 1 MiB")
		}
		input = string(data)
	}
	lines := strings.Split(strings.TrimSuffix(input, "\n"), "\n")
	if len(lines) > 10000 {
		t.Fatal("integration source sample must contain at most 10000 paths")
	}
	if raw := os.Getenv("MANSCAN_TEST_ATTACK_PATH_REPEAT"); raw != "" {
		repeat, err := strconv.Atoi(raw)
		if err != nil || repeat < 1 || repeat > 100 || repeat*len(lines) > 100000 {
			t.Fatal("invalid integration repeat count")
		}
		var expanded strings.Builder
		for i := 0; i < repeat; i++ {
			for _, line := range lines {
				separator := "?"
				if strings.Contains(line, "?") {
					separator = "&"
				}
				if _, err := fmt.Fprintf(&expanded, "%s%sbenchmark_id=%d\n", line, separator, i); err != nil {
					t.Fatal(err)
				}
			}
		}
		input = expanded.String()
		lines = strings.Split(strings.TrimSuffix(input, "\n"), "\n")
	}
	var upstreamActive, upstreamPeak, upstreamCalls atomic.Int32
	transport := http.DefaultTransport
	gateway.client.Transport = gatewayTransport(func(request *http.Request) (*http.Response, error) {
		current := upstreamActive.Add(1)
		upstreamCalls.Add(1)
		for old := upstreamPeak.Load(); current > old; old = upstreamPeak.Load() {
			if upstreamPeak.CompareAndSwap(old, current) {
				break
			}
		}
		response, err := transport.RoundTrip(request)
		if err != nil {
			upstreamActive.Add(-1)
			return nil, err
		}
		response.Body = &attackPathObservedBody{ReadCloser: response.Body, closed: func() { upstreamActive.Add(-1) }}
		return response, nil
	})
	limiter := NewAPIKeyRateLimiter(NewThirdPartyAPIKeyService(gateway.repo, gateway.box))
	classifier := NewAIForceAttackPathClassifier(gateway, limiter, cfg.AI.AttackPathConcurrency)
	shared := classifier.(*aiForceAttackPathClassifier)
	var active, peak, calls atomic.Int32
	observed := attackPathBatchClassifierFunc(func(ctx context.Context, system string, paths []string) ([]int, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); current > old; old = peak.Load() {
			if peak.CompareAndSwap(old, current) {
				break
			}
		}
		calls.Add(1)
		start := time.Now()
		result, err := classifier.Classify(ctx, system, paths)
		shared.mu.Lock()
		gateLimit := shared.limit
		shared.mu.Unlock()
		t.Logf("batch paths=%d removed=%d elapsed=%s success=%v gate_limit=%d", len(paths), len(result), time.Since(start).Round(time.Millisecond), err == nil, gateLimit)
		return result, err
	})
	processor, err := NewHybridAttackPathProcessor(observed, cfg.PromptFilePath(), cfg.AI.AttackPathConcurrency, cfg.AI.AttackPathBatchSize)
	if err != nil {
		t.Fatal(err)
	}
	hybrid := processor.(*hybridAttackPathProcessor)
	rules := hybrid.rules
	counts := &attackPathObservedRules{rules: rules}
	hybrid.rules = counts
	out, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	start := time.Now()
	last := 0
	p, k, err := processor.Process(ctx, strings.NewReader(input), out, len(lines), func(_ context.Context, p, k int) error {
		if p <= last || p > len(lines) || k > p {
			return errors.New("invalid integration progress")
		}
		last = p
		return nil
	})
	t.Logf("local_normal=%d local_malicious=%d model_review=%d", counts.counts[attackPathNormal].Load(), counts.counts[attackPathMalicious].Load(), counts.counts[attackPathUncertain].Load())
	t.Logf("run processed=%d kept=%d batches=%d upstream_requests=%d upstream_peak=%d elapsed=%s", p, k, calls.Load(), upstreamCalls.Load(), upstreamPeak.Load(), time.Since(start).Round(time.Millisecond))
	if err != nil {
		t.Fatalf("real batch processing failed: %v", err)
	}
	if upstreamPeak.Load() > int32(cfg.AI.AttackPathConcurrency) || upstreamActive.Load() != 0 {
		t.Fatal("upstream concurrency exceeded shared budget or leaked")
	}
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	if p != len(lines) || last != p || strings.Count(output, "\n") != k {
		t.Fatal("incomplete output or progress")
	}
	cursor := 0
	if output != "" {
		for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
			for cursor < len(lines) && lines[cursor] != line {
				cursor++
			}
			if cursor == len(lines) {
				t.Fatal("output changed path text or order")
			}
			cursor++
		}
	}
	if path == "" && output != "/api/users\n/api/orders\n" {
		t.Fatal("known integration paths classified incorrectly")
	}
	if expectedPath := os.Getenv("MANSCAN_TEST_ATTACK_PATH_EXPECTED"); expectedPath != "" {
		previous, err := os.ReadFile(expectedPath)
		if err != nil {
			t.Fatal("cannot read comparison sample")
		}
		oldSet, newSet := map[string]bool{}, map[string]bool{}
		for _, line := range strings.Split(strings.TrimSpace(string(previous)), "\n") {
			oldSet[line] = true
		}
		for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
			newSet[line] = true
		}
		added, removed := 0, 0
		for line := range newSet {
			if !oldSet[line] {
				added++
				decision, err := rules.classify(context.Background(), line)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("comparison newly_kept_local_decision=%d", decision)
			}
		}
		for line := range oldSet {
			if !newSet[line] {
				removed++
				decision, err := rules.classify(context.Background(), line)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("comparison newly_removed_local_decision=%d", decision)
			}
		}
		t.Logf("comparison newly_kept=%d newly_removed=%d (previous model output is not ground truth)", added, removed)
	}
	t.Logf("processed=%d kept=%d removed=%d batches=%d peak_batches=%d upstream_requests=%d upstream_peak=%d elapsed=%s", p, k, p-k, calls.Load(), peak.Load(), upstreamCalls.Load(), upstreamPeak.Load(), time.Since(start).Round(time.Millisecond))
}

type attackPathObservedBody struct {
	io.ReadCloser
	once   sync.Once
	closed func()
}

func (b *attackPathObservedBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.closed)
	return err
}

type attackPathObservedRules struct {
	rules  attackPathLocalClassifier
	counts [3]atomic.Int32
}

func (r *attackPathObservedRules) classify(ctx context.Context, raw string) (attackPathDecision, error) {
	decision, err := r.rules.classify(ctx, raw)
	if err == nil {
		r.counts[decision].Add(1)
	}
	return decision, err
}
