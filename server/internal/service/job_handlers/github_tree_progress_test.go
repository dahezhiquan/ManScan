package job_handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/service"
)

type githubProgressFunc func(context.Context, int64, int64, string, string) error

func (f githubProgressFunc) Report(ctx context.Context, current, total int64, phase, message string) error {
	return f(ctx, current, total, phase, message)
}

func TestGitHubTreeProgressShowsWaitsRetriesAndCounts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := NewGitHubTreeClient("private-test-token")
		client.beforeRequest = func(ctx context.Context) error {
			timer := time.NewTimer(6 * time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
		attempts := 0
		client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if filepath.Base(request.URL.Path) == "cves-sha" {
				attempts++
			}
			if filepath.Base(request.URL.Path) == "cves-sha" && attempts < 3 {
				response := githubTreeStalledResponse(request)
				response.Body = io.NopCloser(io.MultiReader(strings.NewReader(`{"tree":[`+strings.Repeat(" ", 1024)), response.Body))
				return response, nil
			}
			return githubTestTreeResponse(request)
		})
		var waiting, receiving, retrying, fallback, finished bool
		var lastCurrent int64
		reporter := githubProgressFunc(func(_ context.Context, current, total int64, phase, message string) error {
			if total != 0 || current < lastCurrent {
				t.Errorf("invalid traversal progress %d/%d after %d", current, total, lastCurrent)
			}
			lastCurrent = current
			if strings.Contains(message, client.Token) {
				t.Error("progress contains credentials")
			}
			switch phase {
			case "github_waiting":
				waiting = waiting || strings.Contains(message, "已等待 5 秒")
			case "github_requesting":
				receiving = receiving || (strings.Contains(message, "已等待 5 秒") && strings.Contains(message, "本次已接收 1.0 KiB"))
			case "github_retrying":
				retrying = retrying || (strings.Contains(message, "请求超时") && strings.Contains(message, "第 3/3 次尝试"))
			case "github_fallback":
				fallback = true
			case "github_finished":
				finished = current == 2 && strings.Contains(message, "已收集 1 个 CVE") && strings.Contains(message, "已处理 2 个目录单元") && strings.Contains(message, "请求 4 次") && strings.Contains(message, "cves")
			}
			return nil
		})
		names, err := client.ListCVEFileNamesWithProgress(context.Background(), "main", reporter)
		if err != nil || len(names) != 1 || !waiting || !receiving || !retrying || fallback || !finished {
			t.Fatalf("names=%v err=%v waiting=%t receiving=%t retry=%t fallback=%t finished=%t", names, err, waiting, receiving, retrying, fallback, finished)
		}
		if client.progress != nil {
			t.Fatal("list progress leaked into reusable client")
		}
	})
}

func TestGitHubTreeProgressFailureCancelsActiveRequestWithoutRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := NewGitHubTreeClient("")
		requests, exited := 0, false
		client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			<-request.Context().Done()
			exited = true
			return nil, request.Context().Err()
		})
		reporter := githubProgressFunc(func(_ context.Context, _, _ int64, _, message string) error {
			if strings.Contains(message, "已等待 5 秒") {
				return context.DeadlineExceeded // A reporter timeout is not a GitHub timeout.
			}
			return nil
		})
		names, err := client.ListCVEFileNamesWithProgress(context.Background(), "main", reporter)
		var progressError *githubTreeProgressError
		if names != nil || !errors.As(err, &progressError) || requests != 1 || !exited {
			t.Fatalf("names=%v err=%v requests=%d exited=%t", names, err, requests, exited)
		}
	})
}

func TestGitHubTreeProgressCancellationStopsHeartbeat(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := NewGitHubTreeClient("")
		client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return githubTreeStalledResponse(request), nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		reports := 0
		reporter := githubProgressFunc(func(_ context.Context, _, _ int64, _, message string) error {
			reports++
			if strings.Contains(message, "已等待 5 秒") {
				cancel()
			}
			return nil
		})
		_, err := client.ListCVEFileNamesWithProgress(ctx, "main", reporter)
		if !errors.Is(err, context.Canceled) || reports != 2 {
			t.Fatalf("err=%v reports=%d", err, reports)
		}
	})
}

func TestGitHubTreeProgressReachesScheduledJobs(t *testing.T) {
	for _, mode := range []string{"cve", "vulnx", "incremental"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			seen := make(map[string]bool)
			var lastCurrent int64
			reporter := githubProgressFunc(func(_ context.Context, current, total int64, phase, message string) error {
				seen[phase] = true
				if mode == "incremental" {
					if current < lastCurrent || total != 3000 || !strings.HasPrefix(message, "VulnX：") {
						t.Errorf("invalid composite progress: %d/%d %s", current, total, message)
					}
					lastCurrent = current
				}
				return nil
			})
			factory := rateLimitedTestClient(rateLimitRoundTripFunc(githubTestTreeResponse))
			var err error
			if mode == "cve" {
				handler := NewCVEFileNamesHandler(root, nil, nil)
				handler.clientFn = factory
				err = handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, reporter)
			} else {
				repo := &vulnxRepositoryStub{existing: map[string]struct{}{"CVE-2026-0001": {}}}
				handler := NewVulnxVulnerabilityUpdateHandler(root, nil, nil, nil, repo)
				handler.githubClientFn = factory
				var progress service.ProgressReporter = reporter
				if mode == "incremental" {
					progress = &sourceProgress{parent: reporter, name: "VulnX", index: 2}
				}
				err = handler.ExecuteWithGitHubKey(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, progress, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			prefix := ""
			if mode == "incremental" {
				prefix = "VulnX."
			}
			for _, phase := range []string{"github_requesting", "github_listing", "github_finished", "writing", "finished"} {
				if !seen[prefix+phase] {
					t.Errorf("missing phase %s", prefix+phase)
				}
			}
		})
	}
}

func TestGitHubTreeTruncationSplitsWithClearProgress(t *testing.T) {
	client := NewGitHubTreeClient("")
	if client.HTTPClient.Timeout != 200*time.Second {
		t.Fatalf("request timeout = %v", client.HTTPClient.Timeout)
	}
	requests, limits := 0, 0
	client.beforeRequest = func(context.Context) error { limits++; return nil }
	client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if filepath.Base(request.URL.Path) != "cves-sha" {
			return githubTestTreeResponse(request)
		}
		body := `{"truncated":true,"tree":[{"path":"CVE-2026-9999.json","type":"blob"}]}`
		if request.URL.Query().Get("recursive") != "1" {
			// Duplicate entries must not schedule duplicate subtree reads.
			body = `{"tree":[{"path":"2026","type":"tree","sha":"year-sha"},{"path":"2026","type":"tree","sha":"year-sha"}]}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})
	var fallback, queued, subtree, finished bool
	reporter := githubProgressFunc(func(_ context.Context, current, total int64, phase, message string) error {
		if total != 0 {
			t.Errorf("unknown total reported as %d", total)
		}
		switch phase {
		case "github_fallback":
			fallback = strings.Contains(message, "被截断") && strings.Contains(message, "部分结果不计入")
		case "github_traversing":
			queued = queued || (strings.Contains(message, "新增 1 个子目录待处理") && strings.Contains(message, "不表示整个子树完成") && strings.Contains(message, "另有 1 个排队"))
			subtree = subtree || (strings.Contains(message, "当前子树完整读取") && strings.Contains(message, "cves/2026"))
		case "github_finished":
			finished = current == 3 && strings.Contains(message, "共 1 个 CVE") && strings.Contains(message, "另有 0 个排队")
		}
		return nil
	})
	names, err := client.ListCVEFileNamesWithProgress(context.Background(), "main", reporter)
	if err != nil || strings.Join(names, ",") != "CVE-2026-0001" || requests != 4 || limits != 4 || !fallback || !queued || !subtree || !finished {
		t.Fatalf("names=%v err=%v requests=%d limits=%d fallback=%t queued=%t subtree=%t finished=%t", names, err, requests, limits, fallback, queued, subtree, finished)
	}
}
