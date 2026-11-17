package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const attackPathBatchMaxBytes = 48 << 10

type batchAttackPathProcessor struct {
	classifier             AttackPathBatchClassifier
	promptFile             string
	concurrency, batchSize int
}

type attackPathBatchResult struct {
	index   int
	removed []int
	err     error
}

// NewBatchAttackPathProcessor uses bounded parallel model calls and ordered output.
func NewBatchAttackPathProcessor(classifier AttackPathBatchClassifier, promptFile string, concurrency, batchSize int) (AttackPathFileProcessor, error) {
	if classifier == nil || strings.TrimSpace(promptFile) == "" || concurrency < 1 || concurrency > 32 || batchSize < 1 || batchSize > 1000 {
		return nil, errors.New("攻击路径批量处理配置不合法")
	}
	path, err := filepath.Abs(promptFile)
	if err != nil {
		return nil, err
	}
	if _, err := loadAttackPathPrompts(path, 1); err != nil {
		return nil, err
	}
	return &batchAttackPathProcessor{classifier: classifier, promptFile: path, concurrency: concurrency, batchSize: batchSize}, nil
}

func (p *batchAttackPathProcessor) Process(ctx context.Context, input io.Reader, output *os.File, total int, progress func(context.Context, int, int) error) (int, int, error) {
	if input == nil || output == nil || total < 1 || total > attackPathMaxLines {
		return 0, 0, ErrInvalidAttackPathInput
	}
	prompts, err := loadAttackPathPrompts(p.promptFile, total)
	if err != nil {
		return 0, 0, fmt.Errorf("加载攻击路径提示词失败: %w", err)
	}
	return p.process(ctx, input, output, total, progress, nil, prompts.system)
}

// process receives the task's prompt snapshot so hybrid preprocessing cannot
// pick up a prompt-file change halfway through an already running task.
func (p *batchAttackPathProcessor) process(ctx context.Context, input io.Reader, output *os.File, total int, progress func(context.Context, int, int) error, decisions io.Writer, system string) (int, int, error) {
	runCtx, cancel := context.WithTimeout(ctx, 24*time.Hour)
	defer cancel()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 4096)
	writer := bufio.NewWriter(output)
	carry := ""
	read, processed, kept := 0, 0, 0
	results := make(chan attackPathBatchResult, p.concurrency)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	// Refill completed requests without waiting for a whole wave. Bound both
	// active requests and uncommitted batches, so a slow prefix cannot retain
	// the entire input in memory. The shared classifier also gates HTTP retries.
	batches := make(map[int][]string)
	pending := make(map[int]attackPathBatchResult)
	next, submitted, active := 0, 0, 0
	eof := false
	for {
		for !eof && active < p.concurrency && submitted-next < 2*p.concurrency {
			if err := runCtx.Err(); err != nil {
				return processed, kept, err
			}
			paths, err := readAttackPathBatch(scanner, &carry, p.batchSize)
			if err != nil {
				return processed, kept, err
			}
			if len(paths) == 0 {
				eof = true
				break
			}
			read += len(paths)
			if read > total {
				return processed, kept, errors.New("input path count changed")
			}
			index := submitted
			batches[index] = paths
			submitted++
			active++
			workers.Add(1)
			go func(index int, paths []string) {
				defer workers.Done()
				removed, err := p.classifier.Classify(runCtx, system, paths)
				if err == nil {
					if removed == nil {
						err = errors.New("missing classification results")
					} else {
						err = validateAttackPathIndexes(removed, len(paths))
					}
				}
				results <- attackPathBatchResult{index: index, removed: removed, err: err}
			}(index, paths)
		}
		if active == 0 {
			break
		}
		var result attackPathBatchResult
		select {
		case result = <-results:
		case <-runCtx.Done():
			return processed, kept, runCtx.Err()
		}
		active--
		if result.err != nil {
			return processed, kept, result.err
		}
		pending[result.index] = result
		for {
			result, ok := pending[next]
			if !ok {
				break
			}
			if err := runCtx.Err(); err != nil {
				return processed, kept, err
			}
			paths := batches[next]
			removed := make([]bool, len(paths))
			for _, index := range result.removed {
				removed[index] = true
			}
			batchKept := 0
			mask := make([]byte, len(paths))
			for index, path := range paths {
				if removed[index] {
					continue
				}
				if _, err := writer.WriteString(path + "\n"); err != nil {
					return processed, kept, err
				}
				batchKept++
				mask[index] = 1
			}
			if err := writer.Flush(); err != nil {
				return processed, kept, err
			}
			if progress != nil {
				if err := progress(runCtx, processed+len(paths), kept+batchKept); err != nil {
					return processed, kept, err
				}
			}
			if decisions != nil {
				if n, err := decisions.Write(mask); err != nil {
					return processed, kept, err
				} else if n != len(mask) {
					return processed, kept, io.ErrShortWrite
				}
			}
			processed += len(paths)
			kept += batchKept
			delete(batches, next)
			delete(pending, next)
			next++
		}
	}
	if processed != total {
		return processed, kept, errors.New("input path count changed")
	}
	return processed, kept, runCtx.Err()
}

func readAttackPathBatch(scanner *bufio.Scanner, carry *string, limit int) ([]string, error) {
	paths := make([]string, 0, limit)
	size := 2
	for len(paths) < limit {
		path := *carry
		*carry = ""
		if path == "" {
			if !scanner.Scan() {
				break
			}
			path = scanner.Text()
		}
		if path == "" || len(path) > 2048 || !utf8.ValidString(path) || strings.ContainsAny(path, "\r\n\x00") {
			return nil, ErrInvalidAttackPathInput
		}
		encoded, err := json.Marshal(indexedAttackPath{Index: len(paths), Path: path})
		if err != nil {
			return nil, err
		}
		if len(paths) > 0 && size+len(encoded)+1 > attackPathBatchMaxBytes {
			*carry = path
			break
		}
		paths = append(paths, path)
		size += len(encoded) + 1
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return paths, nil
}
