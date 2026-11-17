package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ManScan/server/internal/repository"
)

func testAttackPathModelCache(t *testing.T) repository.AttackPathModelCacheRepository {
	t.Helper()
	r, err := repository.NewAttackPathModelCacheRepository(context.Background(), filepath.Join(t.TempDir(), "cache", "decisions.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func TestCachedAttackPathClassifierPersistentMixedDecisions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cache", "decisions.sqlite")
	r, err := repository.NewAttackPathModelCacheRepository(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var batches [][]string
	upstream := attackPathBatchClassifierFunc(func(_ context.Context, _ string, paths []string) ([]int, error) {
		batches = append(batches, append([]string{}, paths...))
		removed := []int{}
		for i, p := range paths {
			if strings.Contains(p, "drop") {
				removed = append(removed, i)
			}
		}
		return removed, nil
	})
	c := NewCachedAttackPathClassifier(upstream, r, "provider", "model")
	got, err := c.Classify(ctx, "system", []string{"/keep", "/drop", "/drop", "/keep"})
	if err != nil || !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatalf("first result=%v err=%v", got, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = repository.NewAttackPathModelCacheRepository(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	c = NewCachedAttackPathClassifier(upstream, r, "provider", "model")
	got, err = c.Classify(ctx, "system", []string{"/drop", "/new-keep", "/keep", "/new-drop", "/new-drop"})
	if err != nil || !reflect.DeepEqual(got, []int{0, 3, 4}) {
		t.Fatalf("mixed result=%v err=%v", got, err)
	}
	got, err = c.Classify(ctx, "system", []string{"/new-keep", "/drop", "/keep"})
	if err != nil || !reflect.DeepEqual(got, []int{1}) || !reflect.DeepEqual(batches, [][]string{{"/keep", "/drop"}, {"/new-keep", "/new-drop"}}) {
		t.Fatalf("warm result=%v batches=%v err=%v", got, batches, err)
	}
}

func TestCachedAttackPathClassifierScopeAndExactInput(t *testing.T) {
	r := testAttackPathModelCache(t)
	var calls int
	upstream := attackPathBatchClassifierFunc(func(context.Context, string, []string) ([]int, error) {
		calls++
		return []int{}, nil
	})
	for i, row := range [][4]string{
		{"a", "m", "s", "/api?q=%2f"},
		{"b", "m", "s", "/api?q=%2f"},
		{"a", "n", "s", "/api?q=%2f"},
		{"a", "m", "t", "/api?q=%2f"},
		{"a", "m", "s", "/api?q=/"},
		{"a", "m", "s", "/api?q=%2F"},
		{"a", "m", "s", "/API?q=%2f"},
	} {
		c := NewCachedAttackPathClassifier(upstream, r, row[0], row[1])
		for j := 0; j < 2; j++ {
			if _, err := c.Classify(context.Background(), row[2], []string{row[3]}); err != nil {
				t.Fatal(err)
			}
		}
		if calls != i+1 {
			t.Fatalf("scope/input change incorrectly reused a decision: %d", calls)
		}
	}
	c := NewCachedAttackPathClassifier(upstream, r, "a", "m").(*cachedAttackPathClassifier)
	c.scope = hashAttackPathCacheParts(c.scope, "new-policy")
	if _, err := c.Classify(context.Background(), "s", []string{"/api?q=%2f"}); err != nil || calls != 8 {
		t.Fatalf("policy invalidation failed calls=%d err=%v", calls, err)
	}
}

func TestCachedAttackPathClassifierRejectsInvalidResults(t *testing.T) {
	for _, mode := range []string{"error", "nil", "duplicate", "negative", "overflow", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			r := testAttackPathModelCache(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			upstream := attackPathBatchClassifierFunc(func(context.Context, string, []string) ([]int, error) {
				calls++
				if calls > 1 {
					return []int{0}, nil
				}
				switch mode {
				case "error":
					return []int{0}, errors.New("upstream failed")
				case "duplicate":
					return []int{0, 0}, nil
				case "negative":
					return []int{-1}, nil
				case "overflow":
					return []int{1}, nil
				case "cancel":
					cancel()
					return []int{}, nil
				default:
					return nil, nil
				}
			})
			c := NewCachedAttackPathClassifier(upstream, r, "p", "m")
			if _, err := c.Classify(ctx, "s", []string{"/test"}); err == nil {
				t.Fatal("invalid result accepted")
			}
			got, err := c.Classify(context.Background(), "s", []string{"/test"})
			if err != nil || !reflect.DeepEqual(got, []int{0}) || calls != 2 {
				t.Fatalf("invalid result poisoned cache: result=%v calls=%d err=%v", got, calls, err)
			}
		})
	}
}

func TestCachedAttackPathClassifierConcurrentOverlap(t *testing.T) {
	r := testAttackPathModelCache(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	firstStarted, secondStarted, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	upstream := attackPathBatchClassifierFunc(func(ctx context.Context, _ string, paths []string) ([]int, error) {
		call := calls.Add(1)
		if call == 1 {
			if !reflect.DeepEqual(paths, []string{"/shared", "/first"}) {
				return nil, errors.New("unexpected first batch")
			}
			close(firstStarted)
		} else if call == 2 {
			if !reflect.DeepEqual(paths, []string{"/second"}) {
				return nil, errors.New("overlapping path sent twice")
			}
			close(secondStarted)
		} else {
			return nil, errors.New("unexpected extra model call")
		}
		select {
		case <-release:
			return []int{0}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	c := NewCachedAttackPathClassifier(upstream, r, "p", "m")
	results := make(chan error, 2)
	go func() {
		got, err := c.Classify(ctx, "s", []string{"/shared", "/first"})
		if err == nil && !reflect.DeepEqual(got, []int{0}) {
			err = errors.New("incorrect first result")
		}
		results <- err
	}()
	select {
	case <-firstStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() {
		got, err := c.Classify(ctx, "s", []string{"/second", "/shared", "/shared"})
		if err == nil && !reflect.DeepEqual(got, []int{0, 1, 2}) {
			err = errors.New("incorrect overlapping result")
		}
		results <- err
	}()
	select {
	case <-secondStarted:
	case <-ctx.Done():
		t.Fatal("independent model work was serialized")
	}
	waitCtx, stopWait := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stopWait()
	if _, err := c.Classify(waitCtx, "s", []string{"/shared"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting cancellation failed: %v", err)
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Classify(ctx, "s", []string{"/shared", "/first", "/second"}); err != nil || calls.Load() != 2 {
		t.Fatalf("warm concurrency result calls=%d err=%v", calls.Load(), err)
	}
}

type failingAttackPathModelCache struct {
	repository.AttackPathModelCacheRepository
	readErr, writeErr error
}

func (r failingAttackPathModelCache) FindByKeys(ctx context.Context, keys []string) (map[string]bool, error) {
	if r.readErr != nil {
		return nil, r.readErr
	}
	return r.AttackPathModelCacheRepository.FindByKeys(ctx, keys)
}

func (r failingAttackPathModelCache) Save(ctx context.Context, decisions map[string]bool) error {
	if r.writeErr != nil {
		return r.writeErr
	}
	return r.AttackPathModelCacheRepository.Save(ctx, decisions)
}

func TestCachedAttackPathClassifierStorageFailure(t *testing.T) {
	for _, readFailure := range []bool{true, false} {
		r := testAttackPathModelCache(t)
		failing := failingAttackPathModelCache{AttackPathModelCacheRepository: r}
		if readFailure {
			failing.readErr = errors.New("unreadable")
		} else {
			failing.writeErr = errors.New("disk full")
		}
		calls := 0
		upstream := attackPathBatchClassifierFunc(func(context.Context, string, []string) ([]int, error) {
			calls++
			return []int{}, nil
		})
		c := NewCachedAttackPathClassifier(upstream, failing, "p", "m")
		if _, err := c.Classify(context.Background(), "s", []string{"/a"}); err == nil {
			t.Fatal("cache error became normal classification")
		}
		if readFailure && calls != 0 {
			t.Fatal("model invoked after failed cache read")
		}
		c = NewCachedAttackPathClassifier(upstream, r, "p", "m")
		before := calls
		if _, err := c.Classify(context.Background(), "s", []string{"/a"}); err != nil || calls != before+1 {
			t.Fatalf("retry after storage recovery failed: calls=%d err=%v", calls, err)
		}
	}
}

func TestCachedAttackPathClassifierHybridLocalPriority(t *testing.T) {
	r := testAttackPathModelCache(t)
	promptFile := testAttackPathPromptFile(t)
	prompts, err := loadAttackPathPrompts(promptFile, 4)
	if err != nil {
		t.Fatal(err)
	}
	upstream := attackPathBatchClassifierFunc(func(context.Context, string, []string) ([]int, error) { return []int{}, nil })
	c := NewCachedAttackPathClassifier(upstream, r, "p", "m")
	// A formerly cached normal model decision must not override local detection.
	if _, err := c.Classify(context.Background(), prompts.system, []string{"/../../etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	var calls int
	upstream = attackPathBatchClassifierFunc(func(_ context.Context, _ string, paths []string) ([]int, error) {
		calls++
		if !reflect.DeepEqual(paths, []string{"/custom/a?host=%60id%60", "/custom/b?host=%60id%60"}) {
			return nil, errors.New("local path reached model")
		}
		return []int{0}, nil
	})
	c = NewCachedAttackPathClassifier(upstream, r, "p", "m")
	processor, err := NewHybridAttackPathProcessor(c, promptFile, 5, 500)
	if err != nil {
		t.Fatal(err)
	}
	input := "/api/users\n/../../etc/passwd\n/custom/a?host=%60id%60\n/custom/b?host=%60id%60\n"
	for i := 0; i < 2; i++ {
		out, err := os.CreateTemp(t.TempDir(), "output")
		if err != nil {
			t.Fatal(err)
		}
		last := 0
		p, k, err := processor.Process(context.Background(), strings.NewReader(input), out, 4, func(_ context.Context, processed, kept int) error {
			last = processed
			return nil
		})
		if closeErr := out.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err != nil || p != 4 || k != 2 || last != 4 {
			t.Fatalf("hybrid p=%d k=%d last=%d err=%v", p, k, last, err)
		}
		data, err := os.ReadFile(out.Name())
		if err != nil || string(data) != "/api/users\n/custom/b?host=%60id%60\n" {
			t.Fatalf("hybrid output mismatch: err=%v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("warm hybrid invoked model: calls=%d", calls)
	}
}
