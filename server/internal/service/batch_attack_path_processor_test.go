package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type attackPathBatchClassifierFunc func(context.Context, string, []string) ([]int, error)

func (f attackPathBatchClassifierFunc) Classify(ctx context.Context, system string, paths []string) ([]int, error) {
	return f(ctx, system, paths)
}

func TestBatchAttackPathProcessorParallelOrdered(t *testing.T) {
	var active, peak atomic.Int32
	var input, want strings.Builder
	for i := 0; i < 1200; i++ {
		path := fmt.Sprintf("/api/%d", i)
		if i%11 == 0 {
			path = "/../../" + path
		} else if _, err := fmt.Fprintln(&want, path); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(&input, path); err != nil {
			t.Fatal(err)
		}
	}
	ready := make(chan struct{})
	var calls atomic.Int32
	classify := attackPathBatchClassifierFunc(func(ctx context.Context, system string, paths []string) ([]int, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); current > old; old = peak.Load() {
			if peak.CompareAndSwap(old, current) {
				break
			}
		}
		if calls.Add(1) == 4 {
			close(ready)
		}
		select {
		case <-ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if strings.Contains(paths[0], "/api/0") {
			time.Sleep(20 * time.Millisecond)
		}
		if system == "" {
			return nil, errors.New("missing classification prompt")
		}
		removed := []int{}
		for i, path := range paths {
			if strings.Contains(path, "../") {
				removed = append(removed, i)
			}
		}
		return removed, nil
	})
	processor, err := NewBatchAttackPathProcessor(classify, testAttackPathPromptFile(t), 4, 100)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	last := 0
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, k, err := processor.Process(ctx, strings.NewReader(input.String()), out, 1200, func(_ context.Context, p, k int) error {
		if p <= last || k > p {
			return errors.New("non-monotonic progress")
		}
		last = p
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != want.String() || p != 1200 || last != p || k != strings.Count(want.String(), "\n") || peak.Load() != 4 || active.Load() != 0 {
		t.Fatalf("incorrect processing: p=%d k=%d peak=%d active=%d", p, k, peak.Load(), active.Load())
	}
}

func TestBatchAttackPathProcessorFailures(t *testing.T) {
	for _, mode := range []string{"model", "invalid_indexes", "nil_indexes", "progress", "cancel", "short_input", "extra_input", "closed_output"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var active atomic.Int32
			classify := attackPathBatchClassifierFunc(func(ctx context.Context, _ string, paths []string) ([]int, error) {
				active.Add(1)
				defer active.Add(-1)
				if paths[0] == "/api/0" {
					switch mode {
					case "model":
						return nil, errors.New("model unavailable")
					case "invalid_indexes":
						return []int{len(paths)}, nil
					case "nil_indexes":
						return nil, nil
					case "cancel":
						cancel()
					}
				}
				if mode == "model" || mode == "invalid_indexes" || mode == "nil_indexes" || mode == "cancel" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return []int{}, nil
			})
			processor, err := NewBatchAttackPathProcessor(classify, testAttackPathPromptFile(t), 2, 1)
			if err != nil {
				t.Fatal(err)
			}
			out, err := os.CreateTemp(t.TempDir(), "output")
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			if mode == "closed_output" {
				if err := out.Close(); err != nil {
					t.Fatal(err)
				}
			}
			total := 2
			if mode == "short_input" {
				total = 3
			}
			if mode == "extra_input" {
				total = 1
			}
			_, _, err = processor.Process(ctx, strings.NewReader("/api/0\n/api/1\n"), out, total, func(context.Context, int, int) error {
				if mode == "progress" {
					return errors.New("lease lost")
				}
				return nil
			})
			if err == nil || active.Load() != 0 {
				t.Fatalf("failure not propagated or workers leaked: %v active=%d", err, active.Load())
			}
		})
	}
}

func TestBatchAttackPathProcessorHundredThousand(t *testing.T) {
	var input strings.Builder
	for i := 0; i < 100000; i++ {
		if _, err := fmt.Fprintf(&input, "/api/%d/%s\n", i, strings.Repeat("<", 90)); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	classify := attackPathBatchClassifierFunc(func(_ context.Context, _ string, paths []string) ([]int, error) {
		indexed := make([]indexedAttackPath, len(paths))
		for i, path := range paths {
			indexed[i] = indexedAttackPath{Index: i, Path: path}
		}
		data, err := json.Marshal(indexed)
		if err != nil {
			return nil, err
		}
		if len(data) > attackPathBatchMaxBytes || len(paths) > 500 {
			return nil, errors.New("batch bound exceeded")
		}
		calls.Add(1)
		return []int{}, nil
	})
	processor, err := NewBatchAttackPathProcessor(classify, testAttackPathPromptFile(t), 16, 500)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	p, k, err := processor.Process(context.Background(), strings.NewReader(input.String()), out, 100000, nil)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if p != 100000 || k != p || string(actual) != input.String() || calls.Load() < 200 {
		t.Fatalf("incomplete large input: p=%d k=%d calls=%d", p, k, calls.Load())
	}
}

func TestBatchAttackPathProcessorRefillAndBackpressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := make(chan string, 6)
	release := make(chan struct{})
	classifier := attackPathBatchClassifierFunc(func(ctx context.Context, _ string, paths []string) ([]int, error) {
		started <- paths[0]
		if paths[0] == "/first" {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []int{}, nil
	})
	processor, err := NewBatchAttackPathProcessor(classifier, testAttackPathPromptFile(t), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	input := "/first\n/second\n/third\n/fourth\n/fifth\n/sixth\n"
	done := make(chan error, 1)
	go func() {
		p, k, err := processor.Process(ctx, strings.NewReader(input), out, 6, nil)
		if err == nil && (p != 6 || k != 6) {
			err = errors.New("incomplete refilled processing")
		}
		done <- err
	}()
	// Always cancel and drain before closing the file, including test failures.
	completed := false
	defer func() {
		cancel()
		if !completed {
			<-done
		}
	}()
	seen := map[string]bool{}
	for len(seen) < 4 {
		select {
		case path := <-started:
			seen[path] = true
		case <-ctx.Done():
			t.Fatal("scheduler waited for the slow batch instead of refilling")
		}
	}
	if !seen["/first"] || !seen["/fourth"] {
		t.Fatal("unexpected refill order")
	}
	select {
	case <-started:
		t.Fatal("uncommitted batches exceeded twice the concurrency")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	err = <-done
	completed = true
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(out.Name())
	if err != nil || string(actual) != input {
		t.Fatal("refilled processing changed output text or order")
	}
}
