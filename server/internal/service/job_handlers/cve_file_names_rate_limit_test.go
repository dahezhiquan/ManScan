package job_handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/service"
)

type scheduledAPIKeysStub struct {
	service.ThirdPartyAPIKeyService
	limit uint32
}

func (s scheduledAPIKeysStub) Get(context.Context, int64) (*dto.ThirdPartyAPIKeyListItem, error) {
	return &dto.ThirdPartyAPIKeyListItem{RateLimitPerMinute: s.limit}, nil
}

func (s scheduledAPIKeysStub) GetPlaintext(context.Context, int64) (*dto.ThirdPartyAPIKeyPlaintextResponse, error) {
	return &dto.ThirdPartyAPIKeyPlaintextResponse{Key: "test-github-token"}, nil
}

type rateLimitRoundTripFunc func(*http.Request) (*http.Response, error)

func (f rateLimitRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type requestLimiterFunc func(context.Context, int64) error

func (f requestLimiterFunc) Wait(ctx context.Context, id int64) error {
	return f(ctx, id)
}

func githubTestTreeResponse(request *http.Request) (*http.Response, error) {
	var body string
	switch filepath.Base(request.URL.Path) {
	case "main":
		body = `{"tree":[{"path":"cves","type":"tree","sha":"cves-sha"}]}`
	case "cves-sha":
		if request.URL.Query().Get("recursive") == "1" {
			body = `{"truncated":true,"tree":[{"path":"CVE-2026-9999.json","type":"blob"}]}`
		} else {
			body = `{"tree":[{"path":"2026","type":"tree","sha":"year-sha"}]}`
		}
	case "year-sha":
		body = `{"tree":[{"path":"CVE-2026-0001.json","type":"blob"}]}`
	default:
		return nil, fmt.Errorf("unexpected tree endpoint %q", request.URL.Path)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func rateLimitedTestClient(transport http.RoundTripper) func(string) *GitHubTreeClient {
	return func(token string) *GitHubTreeClient {
		client := NewGitHubTreeClient(token)
		client.HTTPClient.Transport = transport
		return client
	}
}

func TestCVEFileNamesConcurrentJobsShareAPIKeyLimit(t *testing.T) {
	for _, limit := range []uint32{0, 2} {
		t.Run(fmt.Sprintf("limit_%d", limit), func(t *testing.T) {
			roots := []string{t.TempDir(), t.TempDir()}
			synctest.Test(t, func(t *testing.T) {
				apiKeys := scheduledAPIKeysStub{limit: limit}
				limiter := service.NewAPIKeyRateLimiter(apiKeys)
				var mu sync.Mutex
				var requests []time.Time
				transport := rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					if request.Header.Get("Authorization") != "Bearer test-github-token" {
						return nil, errors.New("configured API Key was not used")
					}
					mu.Lock()
					requests = append(requests, time.Now())
					mu.Unlock()
					return githubTestTreeResponse(request)
				})
				apiKeyID := int64(42)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				results := make(chan error, len(roots))
				started := time.Now()
				for i, root := range roots {
					handler := NewCVEFileNamesHandler(root, apiKeys, limiter)
					handler.clientFn = rateLimitedTestClient(transport)
					job := entity.ScheduledJob{ID: int64(i + 1), APIKeyID: &apiKeyID, ConfigJSON: "{}", ConcurrencyPolicy: "allow"}
					go func() { results <- handler.Execute(ctx, job, entity.ScheduledJobRun{}, nil) }()
				}
				for range roots {
					if err := <-results; err != nil {
						t.Fatal(err)
					}
				}
				if len(requests) != 8 {
					t.Fatalf("GitHub requests = %d, want 4 per job including truncation fallback", len(requests))
				}
				sort.Slice(requests, func(i, j int) bool { return requests[i].Before(requests[j]) })
				if limit == 0 {
					if elapsed := time.Since(started); elapsed != 0 {
						t.Fatalf("unlimited jobs were delayed by %v", elapsed)
					}
				} else {
					for i := 1; i < len(requests); i++ {
						if delta := requests[i].Sub(requests[i-1]); delta < time.Minute/time.Duration(limit) {
							t.Fatalf("requests %d/%d across jobs bypassed shared limit: %v", i-1, i, delta)
						}
					}
				}
				for _, root := range roots {
					content, err := os.ReadFile(filepath.Join(root, "data", "tmp", "cve_data", "cves.txt"))
					if err != nil || string(content) != "CVE-2026-0001\n" {
						t.Fatalf("job output = %q, %v", content, err)
					}
				}
			})
		})
	}
}

func TestCVEFileNamesWithoutAPIKeySkipsSharedLimiter(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "test-env-token")
	limiter := requestLimiterFunc(func(context.Context, int64) error {
		return errors.New("unconfigured API Key must not use the limiter")
	})
	handler := NewCVEFileNamesHandler(t.TempDir(), nil, limiter)
	handler.clientFn = rateLimitedTestClient(rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer test-env-token" {
			return nil, errors.New("GITHUB_TOKEN fallback was not used")
		}
		return githubTestTreeResponse(request)
	}))
	if err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCVEFileNamesCancellationDuringRateLimitPreservesOutput(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprintf("timeout_%t", timeout), func(t *testing.T) {
			root := t.TempDir()
			output := filepath.Join(root, "data", "tmp", "cve_data", "cves.txt")
			if err := writeCVEFileNames(output, []string{"CVE-2025-0001"}, nil, context.Background()); err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				apiKeys := scheduledAPIKeysStub{limit: 1}
				handler := NewCVEFileNamesHandler(root, apiKeys, service.NewAPIKeyRateLimiter(apiKeys))
				requests := 0
				handler.clientFn = rateLimitedTestClient(rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					requests++
					return githubTestTreeResponse(request)
				}))
				ctx, cancel := context.WithCancel(context.Background())
				want := context.Canceled
				if timeout {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
					want = context.DeadlineExceeded
				}
				defer cancel()
				apiKeyID := int64(42)
				result := make(chan error, 1)
				go func() {
					result <- handler.Execute(ctx, entity.ScheduledJob{APIKeyID: &apiKeyID, ConfigJSON: "{}"}, entity.ScheduledJobRun{}, nil)
				}()
				synctest.Wait()
				if !timeout {
					cancel()
				}
				if err := <-result; !errors.Is(err, want) {
					t.Fatalf("waiting job result = %v, want %v", err, want)
				}
				if requests != 1 {
					t.Fatalf("requests after cancellation = %d, want only the initial request", requests)
				}
			})
			content, err := os.ReadFile(output)
			if err != nil || string(content) != "CVE-2025-0001\n" {
				t.Fatalf("cancellation replaced previous output: %q, %v", content, err)
			}
		})
	}
}

func TestCVEFileNamesLimiterFailurePreventsHTTPRequest(t *testing.T) {
	failure := errors.New("API Key configuration is unavailable")
	for _, limiter := range []service.APIKeyRateLimiter{nil, requestLimiterFunc(func(context.Context, int64) error { return failure })} {
		handler := NewCVEFileNamesHandler(t.TempDir(), scheduledAPIKeysStub{}, limiter)
		requests := 0
		handler.clientFn = rateLimitedTestClient(rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			return githubTestTreeResponse(request)
		}))
		apiKeyID := int64(42)
		err := handler.Execute(context.Background(), entity.ScheduledJob{APIKeyID: &apiKeyID, ConfigJSON: "{}"}, entity.ScheduledJobRun{}, nil)
		if err == nil || (limiter != nil && !errors.Is(err, failure)) || requests != 0 {
			t.Fatalf("limiter failure was bypassed: error = %v, HTTP requests = %d", err, requests)
		}
	}
}
