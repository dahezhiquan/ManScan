package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/repository"
)

func TestCanonicalAssetDomainFromURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "https default port",
			url:  "https://App.Example.com/login",
			want: "app.example.com:443",
		},
		{
			name: "http default port",
			url:  "http://app.example.com",
			want: "app.example.com:80",
		},
		{
			name: "explicit port",
			url:  "https://app.example.com:8443/path",
			want: "app.example.com:8443",
		},
		{
			name: "ip with explicit port",
			url:  "http://10.107.71.65:8889/",
			want: "10.107.71.65:8889",
		},
		{
			name: "ip with default https port",
			url:  "https://10.107.71.65/",
			want: "10.107.71.65:443",
		},
		{
			name: "invalid port",
			url:  "https://app.example.com:99999",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := canonicalAssetDomainFromURL(tc.url); got != tc.want {
				t.Fatalf("canonicalAssetDomainFromURL(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

func TestProbeAssetDomainLivenessUsesHTTPXProbe(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	target := "http://localhost:" + parsed.Port()

	result, err := probeAssetDomainLiveness(context.Background(), dto.CreateScanTaskRequest{
		ProbeConcurrency: 2,
		Timeout:          3,
	}, []string{target, target, "http://192.0.2.10"}, nil)
	if err != nil {
		t.Fatalf("probeAssetDomainLiveness() error = %v", err)
	}

	want := "localhost:" + parsed.Port()
	if len(result.Observations) != 1 || result.Observations[0].Domain != want {
		t.Fatalf("Observations = %v, want domain %s", result.Observations, want)
	}
	if len(result.CheckedDomains) != 2 {
		t.Fatalf("CheckedDomains = %v, want localhost and 192.0.2.10", result.CheckedDomains)
	}
}

func TestProbeAssetDomainLivenessRecordsRedirectObservation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><head><title>Final Title</title></head><body>ok</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	target := "http://localhost:" + parsed.Port() + "/start"

	result, err := probeAssetDomainLiveness(context.Background(), dto.CreateScanTaskRequest{
		ProbeConcurrency: 1,
		Timeout:          3,
		MaxRedirects:     3,
		ResponseReadSize: 1024 * 1024,
	}, []string{target}, nil)
	if err != nil {
		t.Fatalf("probeAssetDomainLiveness() error = %v", err)
	}
	if len(result.Observations) != 1 {
		t.Fatalf("Observations = %v, want exactly one", result.Observations)
	}

	observation := result.Observations[0]
	if observation.HTTPStatusCode != http.StatusFound {
		t.Fatalf("HTTPStatusCode = %d, want %d", observation.HTTPStatusCode, http.StatusFound)
	}
	if observation.Title != "Final Title" {
		t.Fatalf("Title = %q, want Final Title", observation.Title)
	}
	if !strings.Contains(observation.Request, "/final") {
		t.Fatalf("Request = %q, want final redirect request", observation.Request)
	}
	if !strings.Contains(observation.Response, "HTTP/1.1 200 OK") || !strings.Contains(observation.Response, "Final Title") {
		t.Fatalf("Response = %q, want final response", observation.Response)
	}
}

func TestAssetDomainRegion(t *testing.T) {
	t.Parallel()

	networkRegions := buildAssetDomainNetworkRegions([]repository.AssetDomainNetworkItem{
		{ItemName: "10.0.0.0/8", SmallCategory: "生产内网"},
		{ItemName: "invalid-cidr", SmallCategory: "无效网段"},
	})
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{
			name:   "ip in network",
			domain: "10.107.71.65:8889",
			want:   "生产内网",
		},
		{
			name:   "ip outside network",
			domain: "192.0.2.10:443",
			want:   "外网",
		},
		{
			name:   "domain with internal label suffix",
			domain: "ai-force.duxiaoman-int.com:443",
			want:   "内网",
		},
		{
			name:   "domain without internal suffix",
			domain: "api.example.com:443",
			want:   "外网",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := assetDomainRegion(tc.domain, networkRegions); got != tc.want {
				t.Fatalf("assetDomainRegion(%q) = %q, want %q", tc.domain, got, tc.want)
			}
		})
	}
}

func TestAssetDomainProbeFinishedMessage(t *testing.T) {
	t.Parallel()

	got := assetDomainProbeFinishedMessage(3, 2)
	want := "扫描前域名资产存活 & 指纹探测完成，本次扫描存活 3 个，不存活 2 个"
	if got != want {
		t.Fatalf("assetDomainProbeFinishedMessage() = %q, want %q", got, want)
	}
}

func TestAssetDomainComponentSummary(t *testing.T) {
	t.Parallel()

	got := assetDomainComponentSummary([]repository.AssetDomainServiceAssetObservation{
		{Domain: "app.example.com:443", AppName: "nginx"},
		{Domain: "api.example.com:443", AppName: "tomcat"},
		{Domain: "app.example.com:443", AppName: "nginx"},
	})
	want := "识别到 2 个组件：nginx、tomcat"
	if got != want {
		t.Fatalf("assetDomainComponentSummary() = %q, want %q", got, want)
	}

	empty := assetDomainComponentSummary(nil)
	if empty != "识别到 0 个组件" {
		t.Fatalf("assetDomainComponentSummary(nil) = %q, want zero summary", empty)
	}
}

func TestWriteAssetDomainFingerprintCacheUsesSnakeCaseComponents(t *testing.T) {
	t.Parallel()

	cachePath := t.TempDir() + "/fingerprints.json"
	err := writeAssetDomainFingerprintCache(cachePath, []assetDomainFingerprintCacheEntry{
		{
			Target: "https://app.example.com/",
			Domain: "app.example.com:443",
			Components: []assetDomainFingerprintCacheComponent{
				{
					Domain:     "app.example.com:443",
					AppName:    "nginx",
					AppVersion: "1.24.0",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("writeAssetDomainFingerprintCache() error = %v", err)
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	var payload []map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	components, ok := payload[0]["components"].([]interface{})
	if !ok || len(components) != 1 {
		t.Fatalf("components = %v, want one component", payload[0]["components"])
	}
	component, ok := components[0].(map[string]interface{})
	if !ok {
		t.Fatalf("component = %v, want object", components[0])
	}
	if component["app_name"] != "nginx" || component["app_version"] != "1.24.0" {
		t.Fatalf("component = %v, want snake_case app fields", component)
	}
	if _, ok := component["AppName"]; ok {
		t.Fatalf("component = %v, must not use Go field names", component)
	}
}
