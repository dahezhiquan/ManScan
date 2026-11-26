package job_handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
)

func TestCVEReleaseSelectionUsesTaskTimezoneAndPreviousUTCRelease(t *testing.T) {
	tests := []struct {
		name         string
		timezone     string
		localTime    string
		fullList     bool
		previousHour string
	}{
		{name: "shanghai midnight runs full list", timezone: "Asia/Shanghai", localTime: "2026-11-26 00:00", fullList: true},
		{name: "shanghai hourly maps to UTC", timezone: "Asia/Shanghai", localTime: "2026-11-26 15:00", previousHour: "2026-11-26T06:00:00Z"},
		{name: "berlin daylight saving offset maps to UTC", timezone: "Europe/Berlin", localTime: "2026-07-26 15:00", previousHour: "2026-07-26T12:00:00Z"},
		{name: "local date differs from UTC date", timezone: "Europe/Berlin", localTime: "2026-11-26 00:30", previousHour: "2026-11-25T22:00:00Z"},
		{name: "UTC date boundary", timezone: "UTC", localTime: "2026-11-26 00:30", previousHour: "2026-11-25T23:00:00Z"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			location, err := time.LoadLocation(test.timezone)
			if err != nil {
				t.Fatal(err)
			}
			localTime, err := time.ParseInLocation("2006-01-02 15:04", test.localTime, location)
			if err != nil {
				t.Fatal(err)
			}
			run := entity.ScheduledJobRun{
				TriggerType: "schedule",
				FireKey:     fmt.Sprintf("incremental:17:%d", localTime.Unix()),
			}
			full, previousHour, err := cveReleaseSelection(run, test.timezone, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			if full != test.fullList {
				t.Fatalf("full list = %t, want %t", full, test.fullList)
			}
			if test.previousHour != "" && previousHour.Format(time.RFC3339) != test.previousHour {
				t.Fatalf("previous release hour = %s, want %s", previousHour.Format(time.RFC3339), test.previousHour)
			}
		})
	}
}

func TestGitHubTreeClientReadsCVEIDsFromHourlyReleaseZIP(t *testing.T) {
	releaseHour := time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC)
	archive := makeReleaseDeltaZip(t, map[string]string{
		"deltaCves/CVE-2026-0002.json":        "{}",
		"deltaCves/CVE-2026-0001.json":        "{}",
		"other/CVE-2026-0002.json":            "{}",
		"other/CVE-2026-0003.json":            "{}",
		"deltaCves/nested/CVE-2026-0004.json": "{}",
		"deltaCves/not-a-cve.json":            "{}",
		"release_notes.md":                    "ignored",
	})
	assetName := "2026-11-26_delta_CVEs_at_0600Z.zip"
	assetURL := "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-11-26_0600Z/" + assetName
	releaseBody, err := json.Marshal(map[string]any{
		"tag_name": "cve_2026-11-26_0600Z",
		"assets":   []map[string]any{{"name": assetName, "size": len(archive), "browser_download_url": assetURL}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var requests []string
	client := NewGitHubTreeClient("test-token")
	client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Method+" "+request.URL.Host+request.URL.Path)
		if strings.HasPrefix(request.URL.Path, "/repos/CVEProject/cvelistV5/releases/tags/") {
			if request.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("release API authorization = %q", request.Header.Get("Authorization"))
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(releaseBody)), Request: request}, nil
		}
		if request.URL.Host == "github.com" && request.URL.Path == "/CVEProject/cvelistV5/releases/download/cve_2026-11-26_0600Z/"+assetName {
			if request.Header.Get("Authorization") != "" {
				t.Error("GitHub token was sent to the public release asset host")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(archive)), ContentLength: int64(len(archive)), Request: request}, nil
		}
		t.Fatalf("unexpected GitHub request: %s %s", request.Method, request.URL)
		return nil, nil
	})
	var limited int
	client.beforeRequest = func(context.Context) error { limited++; return nil }
	got, err := client.ListCVEDeltaIDs(context.Background(), releaseHour)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CVE-2026-0001", "CVE-2026-0002"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CVE IDs = %v, want %v", got, want)
	}
	if limited != 2 || len(requests) != 2 {
		t.Fatalf("requests=%v limiter calls=%d, want two each", requests, limited)
	}
}

func TestGitHubTreeClientRejectsMissingReleaseDelta(t *testing.T) {
	client := NewGitHubTreeClient("")
	client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"tag_name":"cve_2026-11-26_0600Z","assets":[]}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})
	_, err := client.ListCVEDeltaIDs(context.Background(), time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "缺少增量文件") {
		t.Fatalf("ListCVEDeltaIDs() error = %v", err)
	}
}

func TestGitHubReleaseAssetAPIFallback(t *testing.T) {
	const apiURL = "https://api.github.com/repos/CVEProject/cvelistV5/releases/assets/123"
	const assetURL = "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-11-26_0600Z/2026-11-26_delta_CVEs_at_0600Z.zip"
	archive := makeReleaseDeltaZip(t, map[string]string{"deltaCves/CVE-2026-0001.json": "{}"})
	for _, test := range []struct {
		name          string
		apiURL        string
		apiStatus     int
		apiBody       []byte
		apiError      error
		cancel        bool
		browserStatus int
		wantAPI       int
		wantBrowser   int
		wantError     bool
	}{
		{name: "API success skips browser", apiURL: apiURL, wantAPI: 1},
		{name: "HTTP failure falls back", apiURL: apiURL, apiStatus: http.StatusForbidden, wantAPI: 1, wantBrowser: 1},
		{name: "timeout retries then falls back", apiURL: apiURL, apiError: context.DeadlineExceeded, wantAPI: 3, wantBrowser: 1},
		{name: "invalid ZIP falls back", apiURL: apiURL, apiBody: []byte(`{"name":"metadata instead of ZIP"}`), wantAPI: 1, wantBrowser: 1},
		{name: "missing API URL falls back", wantBrowser: 1},
		{name: "untrusted API URL is not requested", apiURL: "https://example.com/assets/123", wantBrowser: 1},
		{name: "wrong repository API is not requested", apiURL: "https://api.github.com/repos/other/repo/releases/assets/123", wantBrowser: 1},
		{name: "wrong asset ID is not requested", apiURL: apiURL + "4", wantBrowser: 1},
		{name: "both downloads fail", apiURL: apiURL, apiStatus: http.StatusNotFound, browserStatus: http.StatusBadGateway, wantAPI: 1, wantBrowser: 1, wantError: true},
		{name: "cancellation skips fallback", apiURL: apiURL, cancel: true, wantAPI: 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			releaseBody, err := json.Marshal(map[string]any{
				"tag_name": "cve_2026-11-26_0600Z",
				"assets":   []map[string]any{{"id": 123, "url": test.apiURL, "name": "2026-11-26_delta_CVEs_at_0600Z.zip", "size": len(archive), "browser_download_url": assetURL}},
			})
			if err != nil {
				t.Fatal(err)
			}
			var apiCalls, browserCalls, limited int
			client := NewGitHubTreeClient("test-token")
			client.beforeRequest = func(context.Context) error { limited++; return nil }
			client.HTTPClient.Transport = rateLimitRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				status, body := http.StatusOK, archive
				switch {
				case strings.Contains(req.URL.Path, "/releases/tags/"):
					body = releaseBody
				case req.URL.String() == apiURL:
					apiCalls++
					if browserCalls != 0 {
						t.Error("API requested after browser fallback")
					}
					if req.Header.Get("Accept") != "application/octet-stream" || req.Header.Get("Authorization") != "Bearer test-token" || req.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
						t.Error("missing API download headers")
					}
					if test.cancel {
						cancel()
						return nil, ctx.Err()
					}
					if test.apiError != nil {
						return nil, test.apiError
					}
					if test.apiStatus != 0 {
						status = test.apiStatus
					}
					if test.apiBody != nil {
						body = test.apiBody
					}
				case req.URL.String() == assetURL:
					browserCalls++
					if req.Header.Get("Authorization") != "" {
						t.Error("token sent to browser download URL")
					}
					if test.browserStatus != 0 {
						status = test.browserStatus
					}
				default:
					t.Fatalf("unexpected request: %s", req.URL)
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: req}, nil
			})
			ids, err := client.ListCVEDeltaIDs(ctx, time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC))
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, want error %t", err, test.wantError)
			}
			if test.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation, got %v", err)
			}
			if test.browserStatus != 0 && (err == nil || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), "HTTP 502")) {
				t.Fatalf("expected both source errors, got %v", err)
			}
			if !test.wantError && !reflect.DeepEqual(ids, []string{"CVE-2026-0001"}) {
				t.Fatalf("CVE IDs = %v", ids)
			}
			if apiCalls != test.wantAPI || browserCalls != test.wantBrowser || limited != 1+apiCalls+browserCalls {
				t.Fatalf("API calls=%d browser calls=%d limiter calls=%d", apiCalls, browserCalls, limited)
			}
		})
	}
}

func TestGitHubReleaseAssetAPIRedirect(t *testing.T) {
	archive := makeReleaseDeltaZip(t, map[string]string{"deltaCves/CVE-2026-0001.json": "{}"})
	for _, test := range []struct {
		name     string
		location string
		allowed  bool
	}{
		{name: "official asset CDN", location: "https://release-assets.githubusercontent.com/file.zip", allowed: true},
		{name: "public GitHub", location: "https://github.com/file.zip", allowed: true},
		{name: "untrusted host", location: "https://example.com/file.zip"},
		{name: "HTTP downgrade", location: "http://release-assets.githubusercontent.com/file.zip"},
		{name: "nonstandard port", location: "https://release-assets.githubusercontent.com:8443/file.zip"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := NewGitHubTreeClient("test-token")
			var redirected bool
			client.HTTPClient.Transport = rateLimitRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "api.github.com" {
					return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{test.location}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
				}
				redirected = true
				if req.Header.Get("Authorization") != "" {
					t.Error("token forwarded to asset host")
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(archive)), ContentLength: int64(len(archive)), Request: req}, nil
			})
			ids, err := client.readReleaseDelta(context.Background(), "https://api.github.com/repos/CVEProject/cvelistV5/releases/assets/123", true)
			if test.allowed != (err == nil) || redirected != test.allowed {
				t.Fatalf("error=%v redirected=%t allowed=%t", err, redirected, test.allowed)
			}
			if test.allowed && !reflect.DeepEqual(ids, []string{"CVE-2026-0001"}) {
				t.Fatalf("CVE IDs = %v", ids)
			}
		})
	}
}

func TestVulnxIncrementalSelectsDeltaOrFullListAndKeepsPreviousFileOnError(t *testing.T) {
	t.Run("hourly delta", func(t *testing.T) {
		root := t.TempDir()
		var fullCalls, deltaCalls int
		var selectedHour time.Time
		fetched := make([]string, 0)
		handler := NewVulnxVulnerabilityUpdateHandler(root, nil, nil, nil, &vulnxRepositoryStub{})
		handler.listFn = func(context.Context) ([]string, error) {
			fullCalls++
			return []string{"CVE-2026-0001"}, nil
		}
		handler.deltaFn = func(_ context.Context, releaseHour time.Time) ([]string, error) {
			deltaCalls++
			selectedHour = releaseHour
			return []string{"CVE-2026-0002"}, nil
		}
		handler.fetchFn = func(_ context.Context, id string) (*repository.VulnerabilityIntelligenceBundle, error) {
			fetched = append(fetched, id)
			return &repository.VulnerabilityIntelligenceBundle{}, nil
		}
		firedAt := time.Date(2026, 11, 26, 15, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
		run := entity.ScheduledJobRun{TriggerType: "schedule", FireKey: fmt.Sprintf("incremental:17:%d", firedAt.Unix())}
		err := handler.ExecuteIncrementalWithGitHubKey(context.Background(), entity.ScheduledJob{ConfigJSON: "{}", Timezone: "Asia/Shanghai"}, run, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if fullCalls != 0 || deltaCalls != 1 || selectedHour.Format(time.RFC3339) != "2026-11-26T06:00:00Z" {
			t.Fatalf("full calls=%d delta calls=%d hour=%s", fullCalls, deltaCalls, selectedHour)
		}
		if !reflect.DeepEqual(fetched, []string{"CVE-2026-0002"}) {
			t.Fatalf("fetched IDs = %v", fetched)
		}
	})

	t.Run("midnight full list", func(t *testing.T) {
		root := t.TempDir()
		var fullCalls, deltaCalls int
		handler := NewVulnxVulnerabilityUpdateHandler(root, nil, nil, nil, &vulnxRepositoryStub{})
		handler.listFn = func(context.Context) ([]string, error) {
			fullCalls++
			return nil, nil
		}
		handler.deltaFn = func(context.Context, time.Time) ([]string, error) {
			deltaCalls++
			return nil, nil
		}
		firedAt := time.Date(2026, 11, 26, 0, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
		run := entity.ScheduledJobRun{TriggerType: "schedule", FireKey: fmt.Sprintf("incremental:17:%d", firedAt.Unix())}
		if err := handler.ExecuteIncrementalWithGitHubKey(context.Background(), entity.ScheduledJob{ConfigJSON: "{}", Timezone: "Asia/Shanghai"}, run, nil, nil); err != nil {
			t.Fatal(err)
		}
		if fullCalls != 1 || deltaCalls != 0 {
			t.Fatalf("full calls=%d delta calls=%d", fullCalls, deltaCalls)
		}
	})

	t.Run("failed delta retains previous list", func(t *testing.T) {
		root := t.TempDir()
		listPath := filepath.Join(root, "data", "tmp", "cve_data", "cves.txt")
		if err := os.MkdirAll(filepath.Dir(listPath), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := writeFileAtomic(listPath, []byte("CVE-2025-12345\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		handler := NewVulnxVulnerabilityUpdateHandler(root, nil, nil, nil, &vulnxRepositoryStub{})
		handler.deltaFn = func(context.Context, time.Time) ([]string, error) {
			return nil, errors.New("release unavailable")
		}
		firedAt := time.Date(2026, 11, 26, 15, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
		run := entity.ScheduledJobRun{TriggerType: "schedule", FireKey: fmt.Sprintf("incremental:17:%d", firedAt.Unix())}
		err := handler.ExecuteIncrementalWithGitHubKey(context.Background(), entity.ScheduledJob{ConfigJSON: "{}", Timezone: "Asia/Shanghai"}, run, nil, nil)
		if err == nil {
			t.Fatal("expected delta failure")
		}
		got, readErr := os.ReadFile(listPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(got) != "CVE-2025-12345\n" {
			t.Fatalf("previous CVE list changed: %q", got)
		}
	})
}

func makeReleaseDeltaZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
