package service

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type hybridAttackPathProcessor struct {
	batch *batchAttackPathProcessor
	rules attackPathLocalClassifier
}

// NewHybridAttackPathProcessor keeps local decisions and sends only uncertain paths to AI.
func NewHybridAttackPathProcessor(classifier AttackPathBatchClassifier, promptFile string, concurrency, batchSize int) (AttackPathFileProcessor, error) {
	batch, err := NewBatchAttackPathProcessor(classifier, promptFile, concurrency, batchSize)
	if err != nil {
		return nil, err
	}
	rules, err := newAttackPathRules()
	if err != nil {
		return nil, err
	}
	return &hybridAttackPathProcessor{batch: batch.(*batchAttackPathProcessor), rules: rules}, nil
}

func (p *hybridAttackPathProcessor) Process(ctx context.Context, input io.Reader, output *os.File, total int, progress func(context.Context, int, int) error) (int, int, error) {
	if input == nil || output == nil || total < 1 || total > attackPathMaxLines {
		return 0, 0, ErrInvalidAttackPathInput
	}
	prompts, err := loadAttackPathPrompts(p.batch.promptFile, total)
	if err != nil {
		return 0, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 24*time.Hour)
	defer cancel()
	dir, err := os.MkdirTemp(filepath.Dir(output.Name()), ".hybrid-")
	if err != nil {
		return 0, 0, err
	}
	defer os.RemoveAll(dir)
	files := make([]*os.File, 0, 4)
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for _, name := range []string{"input", "uncertain", "classified", "decisions"} {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return 0, 0, err
		}
		files = append(files, f)
	}
	original, uncertain, classified, decisions := files[0], files[1], files[2], files[3]
	writers := []*bufio.Writer{bufio.NewWriter(original), bufio.NewWriter(uncertain)}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 4096)
	local := make([]attackPathDecision, 0, total)
	unknown := 0
	carry := ""
	for {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		paths, err := readAttackPathBatch(scanner, &carry, 500)
		if err != nil {
			return 0, 0, err
		}
		if len(paths) == 0 {
			break
		}
		decisions, err := classifyAttackPathBatch(ctx, p.rules, paths)
		if err != nil {
			return 0, 0, err
		}
		for i, path := range paths {
			if len(local) >= total {
				return 0, 0, errors.New("input path count changed")
			}
			decision := decisions[i]
			local = append(local, decision)
			if _, err := writers[0].WriteString(path + "\n"); err != nil {
				return 0, 0, err
			}
			if decision == attackPathUncertain {
				unknown++
				if _, err := writers[1].WriteString(path + "\n"); err != nil {
					return 0, 0, err
				}
			}
		}
	}
	if len(local) != total {
		return 0, 0, errors.New("input path count changed")
	}
	for _, writer := range writers {
		if err := writer.Flush(); err != nil {
			return 0, 0, err
		}
	}
	if _, err := original.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}
	if _, err := uncertain.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}
	reader := bufio.NewScanner(original)
	reader.Buffer(make([]byte, 4096), 4096)
	writer := bufio.NewWriter(output)
	processed, kept, modelCommitted := 0, 0, 0
	// Merge only the decided prefix. Positional mask bytes preserve even
	// duplicate path occurrences and never match results by a mutable string.
	merge := func(available int) error {
		before := processed
		for processed < total {
			if err := ctx.Err(); err != nil {
				return err
			}
			decision := local[processed]
			if decision == attackPathUncertain {
				if modelCommitted >= available {
					break
				}
				var mask [1]byte
				if _, err := decisions.ReadAt(mask[:], int64(modelCommitted)); err != nil {
					return err
				}
				if mask[0] > 1 {
					return errors.New("invalid classification decision")
				}
				decision = attackPathMalicious
				if mask[0] == 1 {
					decision = attackPathNormal
				}
				modelCommitted++
			}
			if !reader.Scan() {
				if err := reader.Err(); err != nil {
					return err
				}
				return io.ErrUnexpectedEOF
			}
			if decision == attackPathNormal {
				if _, err := writer.WriteString(reader.Text() + "\n"); err != nil {
					return err
				}
				kept++
			}
			processed++
		}
		if err := writer.Flush(); err != nil {
			return err
		}
		if progress != nil && processed > before {
			return progress(ctx, processed, kept)
		}
		return nil
	}
	if err := merge(0); err != nil {
		return processed, kept, err
	}
	if unknown > 0 {
		// Batch progress fires before decision writes; synchronize through the
		// writer so a mask is visible to the reader before advancing the prefix.
		sink := &attackPathDecisionWriter{file: decisions, merge: merge}
		if _, _, err := p.batch.process(ctx, uncertain, classified, unknown, nil, sink, prompts.system); err != nil {
			return processed, kept, err
		}
	}
	if processed != total || modelCommitted != unknown {
		return processed, kept, errors.New("incomplete hybrid classification")
	}
	return processed, kept, ctx.Err()
}

// Bound CPU work and retain one result per position. Each Coraza transaction
// belongs to one worker; the compiled immutable WAF is shared across workers.
func classifyAttackPathBatch(ctx context.Context, rules attackPathLocalClassifier, paths []string) ([]attackPathDecision, error) {
	results := make([]attackPathDecision, len(paths))
	errorsByIndex := make([]error, len(paths))
	workers := min(5, runtime.GOMAXPROCS(0), len(paths))
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(offset int) {
			defer group.Done()
			for i := offset; i < len(paths); i += workers {
				results[i], errorsByIndex[i] = rules.classify(ctx, paths[i])
				if errorsByIndex[i] != nil {
					return
				}
			}
		}(worker)
	}
	group.Wait()
	for _, err := range errorsByIndex {
		if err != nil {
			return nil, err
		}
	}
	return results, ctx.Err()
}

type attackPathDecisionWriter struct {
	file  *os.File
	count int
	merge func(int) error
}

func (w *attackPathDecisionWriter) Write(data []byte) (int, error) {
	n, err := w.file.Write(data)
	if err != nil {
		return n, err
	}
	w.count += n
	if err := w.merge(w.count); err != nil {
		return n, err
	}
	return n, nil
}
