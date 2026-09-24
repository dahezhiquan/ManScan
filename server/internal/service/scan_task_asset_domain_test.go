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
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/scanruntime"
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
	}, []string{target, target, "http://192.0.2.10"}, nil, nil)
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
	}, []string{target}, nil, nil)
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
	if len(result.FingerprintTargets) != 1 {
		t.Fatalf("FingerprintTargets = %v, want exactly one target", result.FingerprintTargets)
	}
	if result.FingerprintTargets[0].Input != target {
		t.Fatalf("FingerprintTargets[0].Input = %q, want original target %q", result.FingerprintTargets[0].Input, target)
	}
	if !strings.HasSuffix(result.FingerprintTargets[0].FinalURL, "/final") {
		t.Fatalf("FingerprintTargets[0].FinalURL = %q, want final redirect URL", result.FingerprintTargets[0].FinalURL)
	}
}

func TestProbeAssetDomainLivenessRecordsRequestStats(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	state := &scanruntime.State{}
	if _, err := probeAssetDomainLiveness(context.Background(), dto.CreateScanTaskRequest{
		ProbeConcurrency: 1,
		Timeout:          3,
	}, []string{server.URL}, nil, state); err != nil {
		t.Fatalf("probeAssetDomainLiveness() error = %v", err)
	}

	progress := state.SnapshotProgress()
	if progress.TotalRequests != 0 || progress.Requests != 1 {
		t.Fatalf("progress = %+v, want one pre-scan request counted without publishing total", progress)
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
			want:   "未知",
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

func TestAssetDomainComponentCountSummary(t *testing.T) {
	t.Parallel()

	got := assetDomainComponentCountSummary([]repository.AssetDomainServiceAssetObservation{
		{Domain: "app.example.com:443", AppName: "nginx"},
		{Domain: "api.example.com:443", AppName: "tomcat"},
		{Domain: "app.example.com:443", AppName: "nginx"},
	})
	want := "共识别到 2 个组件"
	if got != want {
		t.Fatalf("assetDomainComponentCountSummary() = %q, want %q", got, want)
	}

	empty := assetDomainComponentCountSummary(nil)
	if empty != "共识别到 0 个组件" {
		t.Fatalf("assetDomainComponentCountSummary(nil) = %q, want zero summary", empty)
	}
}

func TestRecordAssetDomainFingerprintObservationsCountsUniqueTechResults(t *testing.T) {
	t.Parallel()

	state := &scanruntime.State{}
	recordAssetDomainFingerprintObservations(state, []repository.AssetDomainServiceAssetObservation{
		{Domain: "example.com:443", AppName: "nginx"},
		{Domain: "example.com:443", AppName: "Nginx"},
		{Domain: "example.com:443", AppName: "php"},
	})

	summary := state.SnapshotResultSummary()
	if summary.TechCount != 2 {
		t.Fatalf("TechCount = %d, want 2 unique fingerprint observations", summary.TechCount)
	}
	if summary.InfoCount != 0 {
		t.Fatalf("InfoCount = %d, want fingerprint observations excluded from info count", summary.InfoCount)
	}
}

func TestAssetDomainServiceAssetQueueStreamsFingerprintObservations(t *testing.T) {
	t.Parallel()

	state := &scanruntime.State{}
	svc := &scanTaskService{
		assetDomainRepository: &assetDomainRepositoryStub{},
		templateRepository: &templateRepositoryStub{
			details: map[string]*dto.TemplateDetail{
				"nginx-detect": {
					ID:       "nginx-detect",
					Name:     "Nginx Detect",
					Tags:     []string{"tech", "nginx", "http"},
					Severity: "info",
				},
			},
		},
	}
	queue := newAssetDomainServiceAssetQueue(svc, state)
	queue.Enqueue(assetDomainServiceAssetResultEvent{payload: map[string]interface{}{
		"template-id":       "nginx-detect",
		"matched-at":        "https://app.example.com:8443/login",
		"host":              "app.example.com",
		"port":              "8443",
		"matcher-name":      "nginx",
		"extracted-results": []interface{}{"nginx:1.24.0"},
		"info": map[string]interface{}{
			"name": "Nginx Detect",
			"tags": []interface{}{"tech", "nginx", "http"},
		},
	}})
	queue.CloseAndWait()

	summary := state.SnapshotResultSummary()
	if summary.TechCount != 1 {
		t.Fatalf("TechCount = %d, want one streamed active fingerprint result", summary.TechCount)
	}
	events := state.FrontendEventsBefore(0, 10).Events
	if len(events) == 0 || !strings.Contains(events[len(events)-1].Message, "nginx") {
		t.Fatalf("events = %+v, want streamed nginx fingerprint event", events)
	}
}

func TestAssetDomainFingerprintResultUsesOriginalTargetDomainAfterRedirect(t *testing.T) {
	t.Parallel()

	svc := &scanTaskService{
		templateRepository: &templateRepositoryStub{
			details: map[string]*dto.TemplateDetail{
				"openresty-detect": {
					ID:       "openresty-detect",
					Name:     "OpenResty Detect",
					Tags:     []string{"tech", "openresty", "http"},
					Severity: "info",
				},
			},
		},
	}
	resolver := newAssetDomainFingerprintTargetResolver([]assetDomainFingerprintTarget{{
		Input:    "https://anquan.duxiaoman-int.com",
		Domain:   "anquan.duxiaoman-int.com:443",
		FinalURL: "https://sso.duxiaoman-int.com/login",
	}})

	observations, err := svc.buildAssetDomainServiceAssetsFromPayloadWithResolver(context.Background(), map[string]interface{}{
		"template-id":  "openresty-detect",
		"matched-at":   "https://sso.duxiaoman-int.com/login",
		"host":         "sso.duxiaoman-int.com",
		"port":         "443",
		"matcher-name": "openresty",
		"info": map[string]interface{}{
			"name": "OpenResty Detect",
			"tags": []interface{}{"tech", "openresty", "http"},
		},
	}, resolver)
	if err != nil {
		t.Fatalf("buildAssetDomainServiceAssetsFromPayloadWithResolver() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("observations = %+v, want one component", observations)
	}
	if observations[0].Domain != "anquan.duxiaoman-int.com:443" {
		t.Fatalf("observations[0].Domain = %q, want original target endpoint", observations[0].Domain)
	}
}

func TestAssetDomainFingerprintResultPrefersOriginalInputForSharedRedirect(t *testing.T) {
	t.Parallel()

	svc := &scanTaskService{
		templateRepository: &templateRepositoryStub{
			details: map[string]*dto.TemplateDetail{
				"openresty-detect": {
					ID:       "openresty-detect",
					Name:     "OpenResty Detect",
					Tags:     []string{"tech", "openresty", "http"},
					Severity: "info",
				},
			},
		},
	}
	resolver := newAssetDomainFingerprintTargetResolver([]assetDomainFingerprintTarget{
		{
			Input:    "https://anquan.duxiaoman-int.com",
			Domain:   "anquan.duxiaoman-int.com:443",
			FinalURL: "https://sso.duxiaoman-int.com/login",
		},
		{
			Input:    "https://baoxian.duxiaoman-int.com",
			Domain:   "baoxian.duxiaoman-int.com:443",
			FinalURL: "https://sso.duxiaoman-int.com/login",
		},
	})

	observations, err := svc.buildAssetDomainServiceAssetsFromPayloadWithResolver(context.Background(), map[string]interface{}{
		"template-id":  "openresty-detect",
		"input":        "https://baoxian.duxiaoman-int.com",
		"matched-at":   "https://sso.duxiaoman-int.com/login",
		"host":         "sso.duxiaoman-int.com",
		"port":         "443",
		"matcher-name": "openresty",
		"info": map[string]interface{}{
			"name": "OpenResty Detect",
			"tags": []interface{}{"tech", "openresty", "http"},
		},
	}, resolver)
	if err != nil {
		t.Fatalf("buildAssetDomainServiceAssetsFromPayloadWithResolver() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("observations = %+v, want one component", observations)
	}
	if observations[0].Domain != "baoxian.duxiaoman-int.com:443" {
		t.Fatalf("observations[0].Domain = %q, want original input endpoint", observations[0].Domain)
	}
}

func TestAssetDomainFingerprintVersionIgnoresProductNameFallback(t *testing.T) {
	t.Parallel()

	svc := &scanTaskService{
		templateRepository: &templateRepositoryStub{
			details: map[string]*dto.TemplateDetail{
				"apache-detect": {
					ID:       "apache-detect",
					Name:     "Apache Detect",
					Tags:     []string{"tech", "apache"},
					Severity: "info",
				},
			},
		},
	}

	observations, err := svc.buildAssetDomainServiceAssetsFromPayload(context.Background(), map[string]interface{}{
		"template-id":       "apache-detect",
		"matched-at":        "https://www.dxmpay.com/",
		"host":              "www.dxmpay.com",
		"port":              "443",
		"extracted-results": []interface{}{"Apache"},
		"info": map[string]interface{}{
			"name": "Apache Detect",
			"tags": []interface{}{"tech", "apache"},
		},
	})
	if err != nil {
		t.Fatalf("buildAssetDomainServiceAssetsFromPayload() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("observations = %+v, want one apache component", observations)
	}
	if observations[0].AppName != "apache" || observations[0].AppVersion != "" {
		t.Fatalf("observation = %+v, want apache with empty version", observations[0])
	}

	observations, err = svc.buildAssetDomainServiceAssetsFromPayload(context.Background(), map[string]interface{}{
		"template-id":       "apache-detect",
		"matched-at":        "https://www.dxmpay.com/",
		"host":              "www.dxmpay.com",
		"port":              "443",
		"extracted-results": []interface{}{"Apache/2.4.57"},
		"info": map[string]interface{}{
			"name": "Apache Detect",
			"tags": []interface{}{"tech", "apache"},
		},
	})
	if err != nil {
		t.Fatalf("buildAssetDomainServiceAssetsFromPayload() with version error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("observations with version = %+v, want one apache component", observations)
	}
	if observations[0].AppName != "apache" || observations[0].AppVersion != "2.4.57" {
		t.Fatalf("observation with version = %+v, want apache 2.4.57", observations[0])
	}
}

func TestStreamAssetDomainFingerprintTemplateResultsRecordsStats(t *testing.T) {
	t.Parallel()

	state := &scanruntime.State{}
	statsTracker := &assetDomainFingerprintTemplateStatsTracker{}
	streamAssetDomainFingerprintTemplateResults(strings.NewReader(strings.Join([]string{
		`{"requests":"3","actual_requests":"2","total":"5","total_known":"1"}`,
		`{"requests":"4","actual_requests":"3","total":"5","total_known":"1"}`,
	}, "\n")), nil, state, statsTracker)

	progress := state.SnapshotProgress()
	if progress.TotalRequests != 5 || progress.Requests != 3 {
		t.Fatalf("progress = %+v, want active fingerprint stats merged", progress)
	}
}

type assetDomainRepositoryStub struct{}

func (s *assetDomainRepositoryStub) List(context.Context, dto.ListAssetDomainsQuery) (*dto.PageResult[repository.AssetDomainListRecord], error) {
	return &dto.PageResult[repository.AssetDomainListRecord]{}, nil
}

func (s *assetDomainRepositoryStub) ListNetworkItems(context.Context) ([]repository.AssetDomainNetworkItem, error) {
	return nil, nil
}

func (s *assetDomainRepositoryStub) SyncObservations(context.Context, []repository.AssetDomainObservation, []string, time.Time) error {
	return nil
}

func (s *assetDomainRepositoryStub) SyncServiceAssets(context.Context, []repository.AssetDomainServiceAssetObservation, []string, time.Time) error {
	return nil
}

func TestStreamAssetDomainFingerprintTemplateStatsRecordsStderrStats(t *testing.T) {
	t.Parallel()

	state := &scanruntime.State{}
	statsTracker := &assetDomainFingerprintTemplateStatsTracker{}
	streamAssetDomainFingerprintTemplateStats(strings.NewReader(strings.Join([]string{
		`[INF] loading templates`,
		`{"requests":"10","actual_requests":"8","total":"1200","total_known":"1"}`,
	}, "\n")), state, statsTracker)

	progress := state.SnapshotProgress()
	if progress.TotalRequests != 1200 || progress.Requests != 8 {
		t.Fatalf("progress = %+v, want stderr active fingerprint stats merged", progress)
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
