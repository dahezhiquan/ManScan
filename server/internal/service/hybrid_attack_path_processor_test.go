package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHybridAttackPathProcessorPackedUncertainAndOrder(t *testing.T) {
	input := "/api/users\n/../../etc/passwd\n/custom/a?host=%60id%60\n/api/orders\n/custom/a?host=%60id%60\n/custom/b?host=%60id%60\n"
	promptFile := testAttackPathPromptFile(t)
	var calls, reviewed int
	classifier := attackPathBatchClassifierFunc(func(_ context.Context, _ string, paths []string) ([]int, error) {
		calls++
		reviewed += len(paths)
		if strings.Join(paths, "\n") != "/custom/a?host=%60id%60\n/custom/a?host=%60id%60\n/custom/b?host=%60id%60" {
			return nil, errors.New("local paths reached model or uncertain paths split")
		}
		return []int{0, 2}, nil
	})
	processor, err := NewHybridAttackPathProcessor(classifier, promptFile, 1, 500)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	last := 0
	p, k, err := processor.Process(context.Background(), strings.NewReader(input), out, 6, func(_ context.Context, p, k int) error {
		if p <= last || k > p {
			return errors.New("invalid progress")
		}
		if last == 0 {
			// A prompt edit after local preprocessing must not change the
			// snapshot used for this task's pending model batches.
			if err := os.WriteFile(promptFile, []byte("invalid prompt catalog"), 0600); err != nil {
				return err
			}
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
	if string(actual) != "/api/users\n/api/orders\n/custom/a?host=%60id%60\n" || p != 6 || k != 3 || last != 6 || calls != 1 || reviewed != 3 {
		t.Fatalf("incorrect hybrid result: p=%d k=%d calls=%d reviewed=%d", p, k, calls, reviewed)
	}
	dirs, err := filepath.Glob(filepath.Join(filepath.Dir(out.Name()), ".hybrid-*"))
	if err != nil || len(dirs) != 0 {
		t.Fatal("temporary files leaked")
	}
}

func TestHybridAttackPathProcessorLocalAndFailures(t *testing.T) {
	for _, mode := range []string{"local", "model_error", "progress_error", "cancelled", "short_input", "extra_input", "all_uncertain"} {
		t.Run(mode, func(t *testing.T) {
			input := "/api/users\n/../../etc/passwd\n"
			if mode == "model_error" || mode == "all_uncertain" {
				input = "/custom?host=%60id%60\n/custom2?host=%60id%60\n"
			}
			classifier := attackPathBatchClassifierFunc(func(context.Context, string, []string) ([]int, error) {
				if mode == "model_error" {
					return nil, errors.New("model unavailable")
				}
				if mode != "all_uncertain" {
					t.Error("unnecessary model request")
				}
				return []int{}, nil
			})
			processor, err := NewHybridAttackPathProcessor(classifier, testAttackPathPromptFile(t), 1, 500)
			if err != nil {
				t.Fatal(err)
			}
			out, err := os.CreateTemp(t.TempDir(), "output")
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			total := 2
			if mode == "short_input" {
				total = 3
			}
			if mode == "extra_input" {
				total = 1
			}
			last := 0
			p, k, err := processor.Process(ctx, strings.NewReader(input), out, total, func(_ context.Context, p, k int) error {
				if p <= last {
					return errors.New("progress did not advance")
				}
				last = p
				if mode == "progress_error" {
					return errors.New("lease lost")
				}
				return nil
			})
			if mode == "local" || mode == "all_uncertain" {
				wantKept := 1
				if mode == "all_uncertain" {
					wantKept = 2
				}
				if err != nil || p != 2 || k != wantKept || last != 2 {
					t.Fatalf("p=%d k=%d err=%v", p, k, err)
				}
			} else if err == nil {
				t.Fatal("ignored failure")
			}
		})
	}
}

// Clean free-text, unknown fields and repeated parameters must not consume AI calls.
func TestHybridAttackPathProcessorCleanParametersNeverReachModel(t *testing.T) {
	input := "/api/search?q=手机\n/api/items?category=books\n/api/orders?cursor=abc123\n/api/files?path=reports/a.csv\n/api/items?id=1&id=2\n"
	classifier := attackPathBatchClassifierFunc(func(context.Context, string, []string) ([]int, error) {
		t.Error("clean parameters unexpectedly reached model")
		return nil, errors.New("unexpected model request")
	})
	processor, err := NewHybridAttackPathProcessor(classifier, testAttackPathPromptFile(t), 5, 500)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	p, k, err := processor.Process(context.Background(), strings.NewReader(input), out, 5, func(context.Context, int, int) error { return nil })
	if err != nil || p != 5 || k != 5 {
		t.Fatalf("p=%d k=%d err=%v", p, k, err)
	}
	actual, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != input {
		t.Fatal("clean paths changed or were omitted")
	}
}
