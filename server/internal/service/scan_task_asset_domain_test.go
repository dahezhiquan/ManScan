package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

func TestProbeAssetDomainLivenessKeepsNonHTTPFingerprintTargetsForHTTPDown(t *testing.T) {
	t.Parallel()

	target := "192.0.2.10:3306"
	result, err := probeAssetDomainLiveness(context.Background(), dto.CreateScanTaskRequest{
		ProbeConcurrency: 1,
		Timeout:          1,
		Retries:          0,
	}, []string{target}, nil, nil)
	if err != nil {
		t.Fatalf("probeAssetDomainLiveness() error = %v", err)
	}

	if len(result.Observations) != 0 {
		t.Fatalf("Observations = %v, want no HTTP alive observations", result.Observations)
	}
	if len(result.UnresponsiveFingerprintTargets) != 1 {
		t.Fatalf("UnresponsiveFingerprintTargets = %v, want one non-http fingerprint target", result.UnresponsiveFingerprintTargets)
	}
	if result.UnresponsiveFingerprintTargets[0].Input != target {
		t.Fatalf("UnresponsiveFingerprintTargets[0].Input = %q, want original target", result.UnresponsiveFingerprintTargets[0].Input)
	}
	if len(result.Fingerprints) != 1 || result.Fingerprints[0].HTTPAlive {
		t.Fatalf("Fingerprints = %+v, want http_alive=false cache marker", result.Fingerprints)
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
		t.Fatalf("progress = %+v, want one pre-scan request counted as actual request with deferred total", progress)
	}
	if progress.ProgressStatus != "calculating" {
		t.Fatalf("ProgressStatus = %q, want calculating while pre-scan total is deferred", progress.ProgressStatus)
	}
}

func TestAssetDomainRegion(t *testing.T) {
	t.Parallel()

	networkRegions := buildAssetDomainNetworkRegions([]repository.AssetDomainNetworkItem{
		{ItemName: "10.0.0.0/8", SmallCategory: "生产内网"},
		{ItemName: "113.204.105.41-100", SmallCategory: "公网业务段"},
		{ItemName: "203.0.113.100-41", SmallCategory: "反向无效段"},
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
			name:   "ip in last octet range",
			domain: "113.204.105.41:443",
			want:   "公网业务段",
		},
		{
			name:   "ip at last octet range end",
			domain: "113.204.105.100:443",
			want:   "公网业务段",
		},
		{
			name:   "ip outside last octet range",
			domain: "113.204.105.101:443",
			want:   "未知",
		},
		{
			name:   "ip outside network",
			domain: "192.0.2.10:443",
			want:   "未知",
		},
		{
			name:   "reversed last octet range ignored",
			domain: "203.0.113.50:443",
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

func TestAssetHostIPAddressFromTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{
			name:   "ip port service tuple",
			target: "10.72.160.123:8660,mysql",
			want:   "10.72.160.123",
		},
		{
			name:   "ip url",
			target: "http://10.72.160.153:8670",
			want:   "10.72.160.153",
		},
		{
			name:   "domain target ignored",
			target: "redis.internal.example.com:6379,redis",
			want:   "",
		},
		{
			name:   "bare ip",
			target: "10.72.160.153",
			want:   "10.72.160.153",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := assetHostIPAddressFromTarget(tc.target); got != tc.want {
				t.Fatalf("assetHostIPAddressFromTarget(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}
}

func TestSyncAliveAssetDomainsBeforeScanSyncsIPTargetsToAssetHosts(t *testing.T) {
	t.Parallel()

	domainRepo := &assetDomainRepositoryStub{
		networkItems: []repository.AssetDomainNetworkItem{
			{ItemName: "10.72.160.0/24", SmallCategory: "生产内网"},
		},
	}
	hostRepo := &assetHostRepositoryStub{}
	svc := &scanTaskService{
		assetDomainRepository: domainRepo,
		assetHostRepository:   hostRepo,
	}

	if err := svc.syncAliveAssetDomainsBeforeScan(context.Background(), dto.CreateScanTaskRequest{
		DisableHTTPProbe: true,
	}, []string{
		"10.72.160.123:8660,mysql",
		"10.72.160.153:8670,redis",
		"example.com:443",
	}, nil, "", "", nil, nil); err != nil {
		t.Fatalf("syncAliveAssetDomainsBeforeScan() error = %v", err)
	}

	if len(hostRepo.observationValues) != 1 {
		t.Fatalf("SyncObservations calls = %d, want 1", len(hostRepo.observationValues))
	}
	got := hostRepo.observationValues[0]
	if len(got) != 2 {
		t.Fatalf("host observations = %+v, want two IP hosts", got)
	}
	if got[0].IPAddress != "10.72.160.123" || got[0].Region != "生产内网" || !got[0].IsAlive {
		t.Fatalf("first host observation = %+v, want matched alive host", got[0])
	}
	if got[1].IPAddress != "10.72.160.153" || got[1].Region != "生产内网" || !got[1].IsAlive {
		t.Fatalf("second host observation = %+v, want matched alive host", got[1])
	}
	if len(domainRepo.syncObservationValues) != 0 {
		t.Fatalf("domain observations = %+v, want HTTP probe skipped", domainRepo.syncObservationValues)
	}
}

func TestAssetDomainProbeFinishedMessage(t *testing.T) {
	t.Parallel()

	got := assetDomainProbeFinishedMessage(3, 2)
	want := "扫描前域名资产存活 & 指纹探测完成，本次扫描存活 3 个"
	if got != want {
		t.Fatalf("assetDomainProbeFinishedMessage() = %q, want %q", got, want)
	}
}

func TestAssetDomainProbeHostCounts(t *testing.T) {
	t.Parallel()

	alive, notAlive := assetDomainProbeHostCounts(assetDomainLivenessProbeResult{
		Observations:   []repository.AssetDomainObservation{{Domain: "a.example.com"}, {Domain: "b.example.com"}},
		CheckedDomains: []string{"a.example.com", "b.example.com", "c.example.com"},
	})
	if alive != 2 || notAlive != 1 {
		t.Fatalf("assetDomainProbeHostCounts() = (%d, %d), want (2, 1)", alive, notAlive)
	}

	alive, notAlive = assetDomainProbeHostCounts(assetDomainLivenessProbeResult{
		Observations:   []repository.AssetDomainObservation{{Domain: "a.example.com"}, {Domain: "a.example.com"}},
		CheckedDomains: []string{"a.example.com"},
	})
	if alive != 2 || notAlive != 0 {
		t.Fatalf("assetDomainProbeHostCounts() negative remainder = (%d, %d), want (2, 0)", alive, notAlive)
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

func TestSyncAliveAssetDomainsBeforeScanDefersServiceAssetStaleMarking(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	repo := &assetDomainRepositoryStub{}
	svc := &scanTaskService{assetDomainRepository: repo}
	state := &scanruntime.State{}
	queue := newAssetDomainServiceAssetQueue(svc, state)
	defer queue.CloseAndWait()

	if err := svc.syncAliveAssetDomainsBeforeScan(context.Background(), dto.CreateScanTaskRequest{
		AutomaticScan:    true,
		ProbeConcurrency: 1,
		Timeout:          3,
	}, []string{server.URL}, state, "", "", queue, nil); err != nil {
		t.Fatalf("syncAliveAssetDomainsBeforeScan() error = %v", err)
	}

	if len(repo.syncServiceAssetCheckedDomains) != 1 {
		t.Fatalf("SyncServiceAssets calls = %d, want 1", len(repo.syncServiceAssetCheckedDomains))
	}
	if len(repo.syncObservationCheckedDomains) != 1 {
		t.Fatalf("SyncObservations calls = %d, want 1", len(repo.syncObservationCheckedDomains))
	}
	if got := repo.syncObservationCheckedDomains[0]; len(got) != 0 {
		t.Fatalf("pre-scan SyncObservations checkedDomains = %v, want nil/empty to defer stale marking", got)
	}
	if got := repo.syncServiceAssetCheckedDomains[0]; len(got) != 0 {
		t.Fatalf("pre-scan SyncServiceAssets checkedDomains = %v, want nil/empty to defer stale marking", got)
	}
	if checked := queue.CheckedDomains(); len(checked) != 1 || !strings.Contains(checked[0], ":") {
		t.Fatalf("queue.CheckedDomains() = %v, want probed endpoint recorded", checked)
	}
}

func TestSyncAliveAssetDomainsBeforeScanReusesPreflightCache(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	domain := "localhost:" + parsed.Port()
	taskDir := t.TempDir()
	preflightCachePath := taskDir + "/asset-domain-preflight.json"
	fingerprintCachePath := taskDir + "/asset-domain-fingerprints.json"
	cache := &assetDomainPreflightCache{}
	cache.upsertProbeResults([]assetDomainProbeTargetResult{{
		Target:         server.URL,
		CheckedDomains: []string{domain},
		Observations: []repository.AssetDomainObservation{{
			Domain:         domain,
			HTTPStatusCode: http.StatusNoContent,
		}},
		ServiceAssets: []repository.AssetDomainServiceAssetObservation{{
			Domain:  domain,
			AppName: "nginx",
		}},
		Fingerprints: []assetDomainFingerprintCacheEntry{{
			Target:    server.URL,
			Domain:    domain,
			HTTPAlive: true,
			Components: []assetDomainFingerprintCacheComponent{{
				Domain:  domain,
				AppName: "nginx",
			}},
		}},
		FingerprintTargets: []assetDomainFingerprintTarget{{
			Input:  server.URL,
			Domain: domain,
		}},
	}})
	if err := writeAssetDomainPreflightCache(preflightCachePath, cache); err != nil {
		t.Fatalf("writeAssetDomainPreflightCache() error = %v", err)
	}

	repo := &assetDomainRepositoryStub{}
	svc := &scanTaskService{assetDomainRepository: repo}
	state := &scanruntime.State{}
	queue := newAssetDomainServiceAssetQueue(svc, state)
	defer queue.CloseAndWait()

	if err := svc.syncAliveAssetDomainsBeforeScan(context.Background(), dto.CreateScanTaskRequest{
		AutomaticScan: true,
	}, []string{server.URL}, state, fingerprintCachePath, preflightCachePath, queue, nil); err != nil {
		t.Fatalf("syncAliveAssetDomainsBeforeScan() error = %v", err)
	}

	if got := requests.Load(); got != 0 {
		t.Fatalf("preflight HTTP requests = %d, want 0 when cache is complete", got)
	}
	if progress := state.SnapshotProgress(); progress.Requests != 0 || progress.TotalRequests != 0 {
		t.Fatalf("progress = %+v, want no duplicated preflight request stats", progress)
	}
	if len(repo.syncObservationValues) != 1 || len(repo.syncObservationValues[0]) != 1 {
		t.Fatalf("SyncObservations = %+v, want cached observation synced", repo.syncObservationValues)
	}
	if len(repo.syncServiceAssetObservations) != 1 || len(repo.syncServiceAssetObservations[0]) != 1 {
		t.Fatalf("SyncServiceAssets = %+v, want cached service asset synced", repo.syncServiceAssetObservations)
	}
	data, err := os.ReadFile(fingerprintCachePath)
	if err != nil {
		t.Fatalf("ReadFile fingerprint cache error = %v", err)
	}
	if !strings.Contains(string(data), `"http_alive":true`) || !strings.Contains(string(data), `"nginx"`) {
		t.Fatalf("fingerprint cache = %s, want reused cached fingerprint data", string(data))
	}
}

func TestAssetDomainPreflightCacheRequiresActiveFingerprintForManualScan(t *testing.T) {
	t.Parallel()

	cache := &assetDomainPreflightCache{}
	cache.upsertProbeResults([]assetDomainProbeTargetResult{{
		Target:         "https://app.example.com",
		CheckedDomains: []string{"app.example.com:443"},
		FingerprintTargets: []assetDomainFingerprintTarget{{
			Input:  "https://app.example.com",
			Domain: "app.example.com:443",
		}},
	}})

	completed, pending := cache.splitCompletedTargets([]string{"https://app.example.com"}, dto.CreateScanTaskRequest{})
	if len(completed.CheckedDomains) != 0 || len(pending) != 1 {
		t.Fatalf("manual completed=%+v pending=%v, want target pending before active fingerprint completes", completed, pending)
	}

	cache.markActiveFingerprintDone([]assetDomainFingerprintTarget{{
		Input:  "https://app.example.com",
		Domain: "app.example.com:443",
	}}, []repository.AssetDomainServiceAssetObservation{{
		Domain:  "app.example.com:443",
		AppName: "tomcat",
	}})
	completed, pending = cache.splitCompletedTargets([]string{"https://app.example.com"}, dto.CreateScanTaskRequest{})
	if len(pending) != 0 || len(completed.CheckedDomains) != 1 || len(completed.ServiceAssets) != 1 {
		t.Fatalf("manual completed=%+v pending=%v, want target reused after active fingerprint completes", completed, pending)
	}
}

func TestSyncFinishedAssetDomainObservationsMarksStaleForCompletedTask(t *testing.T) {
	t.Parallel()

	repo := &assetDomainRepositoryStub{}
	svc := &scanTaskService{assetDomainRepository: repo}
	queue := newAssetDomainServiceAssetQueue(svc)
	queue.RecordCheckedDomains([]string{"app.example.com:443", "down.example.com:443"})
	queue.RecordDomainObservations([]repository.AssetDomainObservation{{
		Domain:         "app.example.com:443",
		HTTPStatusCode: http.StatusOK,
	}})
	queue.CloseAndWait()

	svc.syncFinishedAssetDomainObservations(queue, nil)

	if len(repo.syncObservationCheckedDomains) != 1 {
		t.Fatalf("SyncObservations calls = %d, want 1", len(repo.syncObservationCheckedDomains))
	}
	if got := repo.syncObservationCheckedDomains[0]; len(got) != 2 {
		t.Fatalf("final SyncObservations checkedDomains = %v, want completed checked domains", got)
	}
	if got := repo.syncObservationValues[0]; len(got) != 1 || got[0].Domain != "app.example.com:443" {
		t.Fatalf("final SyncObservations observations = %+v, want recorded alive observation", got)
	}
}

func TestSyncFinishedAssetDomainServiceAssetsMarksStaleForCompletedTask(t *testing.T) {
	t.Parallel()

	repo := &assetDomainRepositoryStub{}
	svc := &scanTaskService{assetDomainRepository: repo}
	queue := newAssetDomainServiceAssetQueue(svc)
	queue.RecordCheckedDomains([]string{"app.example.com:443"})
	queue.record([]repository.AssetDomainServiceAssetObservation{{
		Domain:  "app.example.com:443",
		AppName: "nginx",
	}})
	queue.CloseAndWait()

	svc.syncFinishedAssetDomainServiceAssets(queue, nil)

	if len(repo.syncServiceAssetCheckedDomains) != 1 {
		t.Fatalf("SyncServiceAssets calls = %d, want 1", len(repo.syncServiceAssetCheckedDomains))
	}
	if got := repo.syncServiceAssetCheckedDomains[0]; len(got) != 1 || got[0] != "app.example.com:443" {
		t.Fatalf("final SyncServiceAssets checkedDomains = %v, want completed checked domain", got)
	}
	if got := repo.syncServiceAssetObservations[0]; len(got) != 1 || got[0].AppName != "nginx" {
		t.Fatalf("final SyncServiceAssets observations = %+v, want recorded nginx observation", got)
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
		`{"requests":"3","actual_requests":"2","total":"5","pre_cluster_total":"7","total_known":"1"}`,
		`{"requests":"4","actual_requests":"3","total":"5","pre_cluster_total":"7","total_known":"1"}`,
	}, "\n")), nil, state, statsTracker)

	progress := state.SnapshotProgress()
	if progress.TotalRequests != 5 || progress.Requests != 3 {
		t.Fatalf("progress = %+v, want active fingerprint stats merged", progress)
	}
	if progress.PreClusterTotalRequests != 7 {
		t.Fatalf("PreClusterTotalRequests = %d, want 7", progress.PreClusterTotalRequests)
	}
}

func TestRunAssetDomainFingerprintTemplatesRegistersPauseInterrupt(t *testing.T) {
	rootDir := t.TempDir()
	startedPath := filepath.Join(rootDir, "started")
	interruptedPath := filepath.Join(rootDir, "interrupted")
	script := "#!/bin/sh\n" +
		"touch " + startedPath + "\n" +
		"trap 'touch " + interruptedPath + "; exit 0' INT\n" +
		"while true; do sleep 1; done\n"
	if err := os.WriteFile(filepath.Join(rootDir, "manscan"), []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := newScanTaskRuntime(nil)
	svc := &scanTaskService{
		rootDir:               rootDir,
		assetDomainRepository: &assetDomainRepositoryStub{},
	}
	done := make(chan error, 1)
	go func() {
		_, err := svc.runAssetDomainFingerprintTemplates(ctx, dto.CreateScanTaskRequest{}, []assetDomainFingerprintTarget{{
			Input:  "example.com:443",
			Domain: "example.com:443",
		}}, rootDir, &scanruntime.State{}, runtime, false)
		done <- err
	}()

	waitForTestFile(t, startedPath)
	if _, accepted := runtime.RequestPause(); !accepted {
		t.Fatalf("RequestPause() accepted = false, want true")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatalf("active fingerprint process did not exit after pause interrupt")
	}
	waitForTestFile(t, interruptedPath)
}

func waitForTestFile(t *testing.T, path string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected file %s to be created", path)
}

type assetDomainRepositoryStub struct {
	networkItems                   []repository.AssetDomainNetworkItem
	syncObservationValues          [][]repository.AssetDomainObservation
	syncObservationCheckedDomains  [][]string
	syncServiceAssetObservations   [][]repository.AssetDomainServiceAssetObservation
	syncServiceAssetCheckedDomains [][]string
}

func (s *assetDomainRepositoryStub) List(context.Context, dto.ListAssetDomainsQuery) (*dto.PageResult[repository.AssetDomainListRecord], error) {
	return &dto.PageResult[repository.AssetDomainListRecord]{}, nil
}

func (s *assetDomainRepositoryStub) ListNetworkItems(context.Context) ([]repository.AssetDomainNetworkItem, error) {
	return s.networkItems, nil
}

func (s *assetDomainRepositoryStub) SyncObservations(_ context.Context, observations []repository.AssetDomainObservation, checkedDomains []string, _ time.Time) error {
	s.syncObservationValues = append(s.syncObservationValues, append([]repository.AssetDomainObservation(nil), observations...))
	s.syncObservationCheckedDomains = append(s.syncObservationCheckedDomains, append([]string(nil), checkedDomains...))
	return nil
}

func (s *assetDomainRepositoryStub) SyncServiceAssets(_ context.Context, observations []repository.AssetDomainServiceAssetObservation, checkedDomains []string, _ time.Time) error {
	s.syncServiceAssetObservations = append(s.syncServiceAssetObservations, append([]repository.AssetDomainServiceAssetObservation(nil), observations...))
	s.syncServiceAssetCheckedDomains = append(s.syncServiceAssetCheckedDomains, append([]string(nil), checkedDomains...))
	return nil
}

type assetHostRepositoryStub struct {
	observationValues [][]repository.AssetHostObservation
}

func (s *assetHostRepositoryStub) SyncObservations(_ context.Context, observations []repository.AssetHostObservation, _ time.Time) error {
	s.observationValues = append(s.observationValues, append([]repository.AssetHostObservation(nil), observations...))
	return nil
}

func TestStreamAssetDomainFingerprintTemplateStatsRecordsStderrStats(t *testing.T) {
	t.Parallel()

	state := &scanruntime.State{}
	statsTracker := &assetDomainFingerprintTemplateStatsTracker{}
	streamAssetDomainFingerprintTemplateStats(strings.NewReader(strings.Join([]string{
		`[INF] loading templates`,
		`{"requests":"10","actual_requests":"8","total":"1200","pre_cluster_total":"1500","total_known":"1"}`,
	}, "\n")), state, statsTracker)

	progress := state.SnapshotProgress()
	if progress.TotalRequests != 1200 || progress.Requests != 8 {
		t.Fatalf("progress = %+v, want stderr active fingerprint stats merged", progress)
	}
	if progress.PreClusterTotalRequests != 1500 {
		t.Fatalf("PreClusterTotalRequests = %d, want 1500", progress.PreClusterTotalRequests)
	}
}

func TestAssetDomainFingerprintTemplateStatsCanDeferTotal(t *testing.T) {
	t.Parallel()

	state := &scanruntime.State{}
	statsTracker := &assetDomainFingerprintTemplateStatsTracker{deferTotal: true}
	streamAssetDomainFingerprintTemplateStats(strings.NewReader(
		`{"requests":"4","actual_requests":"3","total":"6","pre_cluster_total":"8","total_known":"1"}`,
	), state, statsTracker)

	progress := state.SnapshotProgress()
	if progress.TotalRequests != 0 || progress.PreClusterTotalRequests != 0 {
		t.Fatalf("progress totals = %d/%d, want deferred active fingerprint totals hidden", progress.TotalRequests, progress.PreClusterTotalRequests)
	}
	if progress.Requests != 3 {
		t.Fatalf("Requests = %d, want active fingerprint actual requests 3", progress.Requests)
	}
	if progress.ProgressStatus != "calculating" {
		t.Fatalf("ProgressStatus = %q, want calculating while active fingerprint total is deferred", progress.ProgressStatus)
	}
}

func TestAssetDomainFingerprintStatsAccumulateAcrossTargetGroups(t *testing.T) {
	t.Parallel()

	state := &scanruntime.State{}
	streamAssetDomainFingerprintTemplateStats(strings.NewReader(
		`{"requests":"4","actual_requests":"3","total":"6","pre_cluster_total":"8","total_known":"1"}`,
	), state, &assetDomainFingerprintTemplateStatsTracker{})
	streamAssetDomainFingerprintTemplateStats(strings.NewReader(
		`{"requests":"2","actual_requests":"2","total":"3","pre_cluster_total":"5","total_known":"1"}`,
	), state, &assetDomainFingerprintTemplateStatsTracker{})

	progress := state.SnapshotProgress()
	if progress.TotalRequests != 9 {
		t.Fatalf("TotalRequests = %d, want alive and non-http target-group totals 9", progress.TotalRequests)
	}
	if progress.Requests != 5 {
		t.Fatalf("Requests = %d, want accumulated fingerprint requests 5", progress.Requests)
	}
	if progress.PreClusterTotalRequests != 13 {
		t.Fatalf("PreClusterTotalRequests = %d, want accumulated fingerprint totals 13", progress.PreClusterTotalRequests)
	}
}

func TestWriteAssetDomainFingerprintCacheUsesSnakeCaseComponents(t *testing.T) {
	t.Parallel()

	cachePath := t.TempDir() + "/fingerprints.json"
	err := writeAssetDomainFingerprintCache(cachePath, []assetDomainFingerprintCacheEntry{
		{
			Target:    "https://app.example.com/",
			Domain:    "app.example.com:443",
			HTTPAlive: true,
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
	if payload[0]["http_alive"] != true {
		t.Fatalf("http_alive = %v, want true", payload[0]["http_alive"])
	}
}
