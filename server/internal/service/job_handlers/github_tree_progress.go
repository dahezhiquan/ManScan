package job_handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"ManScan/server/internal/service"
)

// githubTreeProgress belongs to one list operation, never to a shared client.
type githubTreeProgress struct {
	reporter         service.ProgressReporter
	directory        string
	completed, found int
	requests         atomic.Int64
	received         atomic.Int64
}

type githubTreeProgressError struct{ err error }

func (e *githubTreeProgressError) Error() string {
	return fmt.Sprintf("上报 GitHub 列表进度失败: %v", e.err)
}
func (e *githubTreeProgressError) Unwrap() error { return e.err }

func (p *githubTreeProgress) report(ctx context.Context, phase, message string) error {
	if p == nil || p.reporter == nil {
		return nil
	}
	// Directory names are display-only; bound their length and quote controls.
	directory := []rune(p.directory)
	if len(directory) > 160 {
		directory = append(directory[:160], '…')
	}
	message = fmt.Sprintf("%s；目录 %q；已完成 %d/2 个读取步骤，已发现 %d 个 CVE，已发起 %d 次请求",
		message, string(directory), p.completed, p.found, p.requests.Load())
	// Leave room for the composite task's source prefix in VARCHAR(512).
	if runes := []rune(message); len(runes) > 480 {
		message = string(runes[:479]) + "…"
	}
	// The total is unknown until traversal finishes. Do not report an estimated
	// denominator that would make the displayed percentage jump backwards.
	if err := p.reporter.Report(ctx, int64(p.completed), 0, phase, message); err != nil {
		return &githubTreeProgressError{err: err}
	}
	return ctx.Err()
}

// run reports long waits even when the network has delivered no new bytes.
// Only this goroutine calls the reporter; the worker only updates byte counts.
func (p *githubTreeProgress) run(ctx context.Context, phase, message string, operation func(context.Context) error) error {
	if p == nil || p.reporter == nil {
		return operation(ctx)
	}
	p.received.Store(0)
	if err := p.report(ctx, phase, message); err != nil {
		return err
	}
	started := time.Now()
	operationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- operation(operationCtx) }()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	status := func() string {
		value := fmt.Sprintf("%s，已等待 %d 秒", message, int(time.Since(started)/time.Second))
		if phase == "github_requesting" {
			value += fmt.Sprintf("，已接收 %.1f KiB", float64(p.received.Load())/1024)
		}
		return value
	}
	for {
		select {
		case err := <-done:
			if err != nil {
				return err
			}
			return p.report(ctx, phase, strings.Replace(status(), "已等待", "耗时", 1)+"，已完成")
		case <-ctx.Done():
			cancel()
			<-done
			return ctx.Err()
		case <-ticker.C:
			if err := p.report(ctx, phase, status()); err != nil {
				cancel()
				<-done
				return err
			}
		}
	}
}

type githubTreeProgressReader struct {
	reader   io.Reader
	progress *githubTreeProgress
}

func (r githubTreeProgressReader) Read(data []byte) (int, error) {
	n, err := r.reader.Read(data)
	r.progress.received.Add(int64(n))
	return n, err
}

func githubTreeRetryReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "请求超时"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "响应体提前结束"
	}
	return "临时网络错误"
}
