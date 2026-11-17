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
	input := "/api/users\n/../../etc/passwd\n/custom/a?q=free+text\n/api/orders\n/custom/a?q=free+text\n/custom/b?q=free+text\n"
	promptFile := testAttackPathPromptFile(t)
	var calls, reviewed int
	classifier := attackPathBatchClassifierFunc(func(_ context.Context, _ string, paths []string) ([]int, error) {
		calls++
		reviewed += len(paths)
		if strings.Join(paths, "\n") != "/custom/a?q=free+text\n/custom/a?q=free+text\n/custom/b?q=free+text" {
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
	if string(actual) != "/api/users\n/api/orders\n/custom/a?q=free+text\n" || p != 6 || k != 3 || last != 6 || calls != 1 || reviewed != 3 {
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
				input = "/custom?q=free+text\n/custom2?q=free+text\n"
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
