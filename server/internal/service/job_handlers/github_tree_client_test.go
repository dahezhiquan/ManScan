package job_handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"ManScan/server/internal/model/entity"
)

type githubTreeBodyReader func([]byte) (int, error)

func (f githubTreeBodyReader) Read(p []byte) (int, error) { return f(p) }

func githubTreeStalledResponse(request *http.Request) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
		Body: io.NopCloser(githubTreeBodyReader(func([]byte) (int, error) {
			<-request.Context().Done()
			return 0, request.Context().Err()
		})),
	}
}

func TestGitHubTreeRetriesIncompleteResponse(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "incomplete_json", true: "body_timeout"}[timeout], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := NewGitHubTreeClient("")
				requests, limits := 0, 0
				client.beforeRequest = func(context.Context) error { limits++; return nil }
				client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					requests++
					if requests == 1 {
						if timeout {
							return githubTreeStalledResponse(request), nil
						}
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"tree":[`)), Request: request}, nil
					}
					return githubTestTreeResponse(request)
				})
				started := time.Now()
				tree, err := client.getTree(context.Background(), "year-sha", false)
				if err != nil || len(tree.Tree) != 1 || requests != 2 || limits != 2 {
					t.Fatalf("tree=%+v err=%v requests=%d limits=%d", tree, err, requests, limits)
				}
				wantElapsed := time.Second
				if timeout {
					wantElapsed += client.HTTPClient.Timeout
				}
				if elapsed := time.Since(started); elapsed != wantElapsed {
					t.Fatalf("elapsed=%v, want %v", elapsed, wantElapsed)
				}
			})
		})
	}
}

func TestGitHubTreeTimeoutDoesNotSplitSubtrees(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := NewGitHubTreeClient("")
		requests, limits, recursiveAttempts, directAttempts := 0, 0, 0, 0
		client.beforeRequest = func(context.Context) error { limits++; return nil }
		client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			if filepath.Base(request.URL.Path) == "cves-sha" {
				if request.URL.Query().Get("recursive") == "1" {
					recursiveAttempts++
					return githubTreeStalledResponse(request), nil
				}
				directAttempts++
			}
			return githubTestTreeResponse(request)
		})
		names, err := client.ListCVEFileNames(context.Background(), "main")
		if !errors.Is(err, context.DeadlineExceeded) || names != nil {
			t.Fatalf("names=%v err=%v", names, err)
		}
		if recursiveAttempts != 3 || directAttempts != 0 || requests != 4 || limits != requests {
			t.Fatalf("recursive=%d direct=%d requests=%d limits=%d", recursiveAttempts, directAttempts, requests, limits)
		}
	})
}

func TestGitHubTreeCancellationStopsRequests(t *testing.T) {
	for _, stage := range []string{"body", "backoff"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := NewGitHubTreeClient("")
				requests := 0
				client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					requests++
					if filepath.Base(request.URL.Path) == "main" {
						return githubTestTreeResponse(request)
					}
					if stage == "body" {
						return githubTreeStalledResponse(request), nil
					}
					return nil, io.ErrUnexpectedEOF
				})
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				names, err := client.ListCVEFileNames(ctx, "main")
				if !errors.Is(err, context.DeadlineExceeded) || names != nil || requests != 2 {
					t.Fatalf("names=%v err=%v requests=%d", names, err, requests)
				}
			})
		})
	}
}

func TestGitHubTreePermanentFailureDoesNotRetryOrFallback(t *testing.T) {
	for _, failure := range []string{"unauthorized", "forbidden", "rate_limited", "invalid_json", "missing_tree", "limiter_timeout"} {
		t.Run(failure, func(t *testing.T) {
			client := NewGitHubTreeClient("")
			requests, limits := 0, 0
			client.beforeRequest = func(context.Context) error {
				limits++
				if failure == "limiter_timeout" && limits == 2 {
					return context.DeadlineExceeded
				}
				return nil
			}
			client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests++
				if requests == 1 {
					return githubTestTreeResponse(request)
				}
				status, body := http.StatusOK, `{}`
				switch failure {
				case "unauthorized":
					status = http.StatusUnauthorized
				case "forbidden":
					status = http.StatusForbidden
				case "rate_limited":
					status = http.StatusTooManyRequests
				case "invalid_json":
					body = `<html>unavailable</html>`
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
			})
			names, err := client.ListCVEFileNames(context.Background(), "main")
			wantRequests := 2
			if failure == "limiter_timeout" {
				wantRequests = 1
			}
			if err == nil || names != nil || requests != wantRequests || limits != 2 {
				t.Fatalf("names=%v err=%v requests=%d limits=%d", names, err, requests, limits)
			}
		})
	}
}

func TestCVEFileNamesExhaustedTreeRetriesPreserveOutput(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "data", "tmp", "cve_data", "cves.txt")
	if err := writeCVEFileNames(output, []string{"CVE-2025-0001"}, nil, context.Background()); err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		handler := NewCVEFileNamesHandler(root, nil, nil)
		requests := 0
		handler.clientFn = rateLimitedTestClient(rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			if filepath.Base(request.URL.Path) == "main" {
				return githubTestTreeResponse(request)
			}
			return githubTreeStalledResponse(request), nil
		}))
		err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, nil)
		if err == nil || !strings.Contains(err.Error(), "read cves tree") || requests != 4 {
			t.Fatalf("err=%v requests=%d", err, requests)
		}
	})
	content, err := os.ReadFile(output)
	if err != nil || string(content) != "CVE-2025-0001\n" {
		t.Fatalf("previous output=%q err=%v", content, err)
	}
}

func TestCVEFileNamesTruncatedDirectTreePreservesOutput(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "data", "tmp", "cve_data", "cves.txt")
	if err := writeCVEFileNames(output, []string{"CVE-2025-0001"}, nil, context.Background()); err != nil {
		t.Fatal(err)
	}
	handler := NewCVEFileNamesHandler(root, nil, nil)
	requests := 0
	handler.clientFn = rateLimitedTestClient(rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if filepath.Base(request.URL.Path) == "main" {
			return githubTestTreeResponse(request)
		}
		if filepath.Base(request.URL.Path) != "cves-sha" {
			t.Errorf("unexpected split request: %s", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"truncated":true,"tree":[{"path":"CVE-2026-9999.json","type":"blob"}]}`)), Request: request}, nil
	}))
	err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, nil)
	if err == nil || !strings.Contains(err.Error(), "直接目录列表仍被截断") || requests != 3 {
		t.Fatalf("err=%v requests=%d", err, requests)
	}
	content, err := os.ReadFile(output)
	if err != nil || string(content) != "CVE-2025-0001\n" {
		t.Fatalf("previous output=%q err=%v", content, err)
	}
}
