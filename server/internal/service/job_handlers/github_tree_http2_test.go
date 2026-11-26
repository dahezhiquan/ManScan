package job_handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"ManScan/server/internal/model/entity"

	"golang.org/x/net/http2"
)

func githubTreeResetResponse(request *http.Request, code http2.ErrCode) *http.Response {
	partial := strings.NewReader(`{"tree":[{"path":"CVE-2026-9999.json","type":"blob"},`)
	reader := io.MultiReader(partial, githubTreeBodyReader(func([]byte) (int, error) {
		return 0, http2.StreamError{StreamID: 287, Code: code, Cause: errors.New("received from peer")}
	}))
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(reader), Request: request}
}

func TestGitHubTreeRetriesHTTP2StreamReset(t *testing.T) {
	for _, code := range []http2.ErrCode{http2.ErrCodeCancel, http2.ErrCodeRefusedStream, http2.ErrCodeInternal} {
		for _, stage := range []string{"request", "body"} {
			t.Run(code.String()+"/"+stage, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					client := NewGitHubTreeClient("")
					requests, limits := 0, 0
					client.beforeRequest = func(context.Context) error { limits++; return nil }
					client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
						requests++
						if requests < 3 {
							if stage == "request" {
								return nil, http2.StreamError{StreamID: 287, Code: code}
							}
							return githubTreeResetResponse(request, code), nil
						}
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"tree":[{"path":"CVE-2026-0001.json","type":"blob"}]}`)), Request: request}, nil
					})
					started := time.Now()
					tree, err := client.getTree(context.Background(), "cves-sha", true)
					if err != nil || len(tree.Tree) != 1 || tree.Tree[0].Path != "CVE-2026-0001.json" || requests != 3 || limits != 3 {
						t.Fatalf("tree=%+v err=%v requests=%d limits=%d", tree, err, requests, limits)
					}
					if elapsed := time.Since(started); elapsed != 3*time.Second {
						t.Fatalf("backoff = %v, want 1s + 2s", elapsed)
					}
				})
			})
		}
	}
}

func TestGitHubTreeHTTP2ExhaustedRetriesPreserveOutput(t *testing.T) {
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
			if filepath.Base(request.URL.Path) != "cves-sha" || request.URL.Query().Get("recursive") != "1" {
				t.Errorf("unexpected traversal fallback: %s", request.URL)
			}
			return githubTreeResetResponse(request, http2.ErrCodeCancel), nil
		}))
		err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, nil)
		var exhausted *githubTreeRetryError
		var reset http2.StreamError
		if !errors.As(err, &exhausted) || !errors.As(err, &reset) || reset.Code != http2.ErrCodeCancel || requests != 4 {
			t.Fatalf("err=%v requests=%d, want exhausted CANCEL and root + 3 attempts", err, requests)
		}
	})
	content, err := os.ReadFile(output)
	if err != nil || string(content) != "CVE-2025-0001\n" {
		t.Fatalf("previous output=%q err=%v", content, err)
	}
}

func TestGitHubTreeHTTP2CancellationStopsRetry(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint(deadline), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				wantErr := context.Canceled
				if deadline {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 500*time.Millisecond)
					defer stop()
					wantErr = context.DeadlineExceeded
				} else {
					time.AfterFunc(500*time.Millisecond, cancel)
				}
				client := NewGitHubTreeClient("")
				requests := 0
				client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					requests++
					return githubTreeResetResponse(request, http2.ErrCodeCancel), nil
				})
				_, err := client.getTree(ctx, "cves-sha", true)
				if !errors.Is(err, wantErr) || requests != 1 {
					t.Fatalf("err=%v requests=%d, want %v and 1 attempt", err, requests, wantErr)
				}
			})
		})
	}
}

func TestGitHubTreeHTTP2NonRetryableErrors(t *testing.T) {
	reset := http2.StreamError{StreamID: 287, Code: http2.ErrCodeCancel}
	for _, err := range []error{
		context.Canceled,
		&githubTreeProgressError{err: reset},
		errors.Join(reset, context.Canceled),
		http2.StreamError{StreamID: 287, Code: http2.ErrCodeProtocol},
		http2.StreamError{StreamID: 287, Code: http2.ErrCodeEnhanceYourCalm},
		errors.New("stream error: stream ID 287; CANCEL; received from peer"),
	} {
		if retryableGitHubTreeError(fmt.Errorf("wrapped: %w", err)) {
			t.Errorf("unexpected retry for %v", err)
		}
	}
	if reason := githubTreeRetryReason(fmt.Errorf("decode: %w", reset)); reason != "HTTP/2 数据流中断（CANCEL）" {
		t.Fatalf("retry reason = %q", reason)
	}
}

// 使用标准 net/http 的真实 HTTP/2 流重置，验证内部错误也能进入重试分支。
func TestGitHubTreeRetriesStandardHTTP2Transport(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol = %s, want HTTP/2", r.Proto)
		}
		if requests.Add(1) == 1 {
			if _, err := io.WriteString(w, `{"tree":[`); err != nil {
				t.Error(err)
				return
			}
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler) // 标准服务端将其转换为 RST_STREAM(INTERNAL_ERROR)。
		}
		if _, err := io.WriteString(w, `{"tree":[]}`); err != nil {
			t.Error(err)
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := NewGitHubTreeClient("")
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.getTree(ctx, "cves-sha", true)
	if err != nil || requests.Load() != 2 {
		t.Fatalf("err=%v requests=%d, want success after 2 attempts", err, requests.Load())
	}
}
