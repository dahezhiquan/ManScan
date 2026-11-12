package job_handlers

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"
)

type vulnxRepositoryStub struct {
	mu             sync.Mutex
	bundles        []*repository.VulnerabilityIntelligenceBundle
	chaitinUpserts int
	err            error
	existing       map[string]struct{}
}

func (s *vulnxRepositoryStub) Stats(context.Context, time.Time) (*repository.VulnerabilityIntelligenceStatsData, error) {
	return &repository.VulnerabilityIntelligenceStatsData{}, nil
}

func (s *vulnxRepositoryStub) List(context.Context, dto.ListVulnerabilityIntelligenceRecordsQuery) (*dto.PageResult[entity.VulnerabilityIntelligenceRecord], error) {
	return &dto.PageResult[entity.VulnerabilityIntelligenceRecord]{}, nil
}

func (s *vulnxRepositoryStub) FindByVulnerabilityID(context.Context, string) (*repository.VulnerabilityIntelligenceDetailData, error) {
	return nil, nil
}

func (s *vulnxRepositoryStub) Replace(_ context.Context, bundle *repository.VulnerabilityIntelligenceBundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.bundles = append(s.bundles, bundle)
	return nil
}

func (s *vulnxRepositoryStub) UpsertAVD(_ context.Context, _ *repository.VulnerabilityIntelligenceBundle) error {
	return nil
}

func (s *vulnxRepositoryStub) UpsertChaitin(_ context.Context, _ *repository.VulnerabilityIntelligenceBundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chaitinUpserts++
	return nil
}

func (s *vulnxRepositoryStub) FindExistingIDs(_ context.Context, _ string, ids []string) (map[string]struct{}, error) {
	found := make(map[string]struct{})
	for _, id := range ids {
		if _, ok := s.existing[id]; ok {
			found[id] = struct{}{}
		}
	}
	return found, nil
}

type vulnxClientStub struct {
	mu       sync.Mutex
	ids      []string
	failures map[string]int
}

func (c *vulnxClientStub) Fetch(_ context.Context, id string) (*repository.VulnerabilityIntelligenceBundle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ids = append(c.ids, id)
	if c.failures[id] > 0 {
		c.failures[id]--
		return nil, errors.New("temporary VulnX error")
	}
	return &repository.VulnerabilityIntelligenceBundle{Record: &entity.VulnerabilityIntelligenceRecord{Source: "vulnx", VulnerabilityID: id}}, nil
}

type vulnxProgressStub struct{ current, total int64 }

type sourceAPIKeysStub struct {
	service.ThirdPartyAPIKeyService
	keys map[int64]string
}

func vulnxTestJobs(githubKeyID *int64) incrementalJobRepositoryStub {
	return incrementalJobRepositoryStub{items: map[string]entity.ScheduledJob{
		CVEFileNamesJobType: {APIKeyID: githubKeyID},
	}}
}

func (s sourceAPIKeysStub) GetPlaintext(_ context.Context, id int64) (*dto.ThirdPartyAPIKeyPlaintextResponse, error) {
	return &dto.ThirdPartyAPIKeyPlaintextResponse{Key: s.keys[id]}, nil
}

func (p *vulnxProgressStub) Report(_ context.Context, current, total int64, _, _ string) error {
	p.current, p.total = current, total
	return nil
}

func TestVulnxUpdateHandlerUsesSeparateSourceKeys(t *testing.T) {
	githubID, vulnxID := int64(11), int64(22)
	keys := sourceAPIKeysStub{keys: map[int64]string{githubID: "github-token", vulnxID: "vulnx-token"}}
	repo := &vulnxRepositoryStub{}
	var waited []int64
	handler := NewVulnxVulnerabilityUpdateHandler(t.TempDir(), vulnxTestJobs(&githubID), keys, requestLimiterFunc(func(_ context.Context, id int64) error {
		waited = append(waited, id)
		return nil
	}), repo)
	handler.githubClientFn = func(token string) *GitHubTreeClient {
		if token != "github-token" {
			t.Errorf("GitHub token = %q", token)
		}
		client := NewGitHubTreeClient(token)
		client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("Authorization") != "Bearer github-token" {
				t.Errorf("GitHub authorization = %q", request.Header.Get("Authorization"))
			}
			return githubTestTreeResponse(request)
		})
		return client
	}
	handler.clientFn = func(key string) *VulnxClient {
		if key != "vulnx-token" {
			t.Errorf("VulnX token = %q", key)
		}
		client := NewVulnxClient(key)
		client.HTTPClient.Transport = rateLimitRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("X-Api-Key") != "vulnx-token" {
				t.Errorf("VulnX authorization = %q", request.Header.Get("X-Api-Key"))
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"cve_id":"CVE-2026-0001"}}`)), Request: request}, nil
		})
		return client
	}
	if err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}", APIKeyID: &vulnxID}, entity.ScheduledJobRun{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(waited) < 2 {
		t.Fatalf("source requests did not use the shared API Key limiter: %v", waited)
	}
	seenVulnxLimit := false
	for _, id := range waited {
		if id == vulnxID {
			seenVulnxLimit = true
		} else if id != githubID {
			t.Fatalf("unexpected limiter key ID = %d", id)
		}
	}
	if !seenVulnxLimit {
		t.Fatalf("VulnX requests did not use key ID %d: %v", vulnxID, waited)
	}
}

func TestVulnxUpdateHandlerRequiresCVEListJob(t *testing.T) {
	handler := NewVulnxVulnerabilityUpdateHandler(t.TempDir(), incrementalJobRepositoryStub{}, nil, nil, &vulnxRepositoryStub{})
	err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, nil)
	if err == nil || !strings.Contains(err.Error(), "读取 CVE 列表任务 API Key 配置失败") {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestVulnxUpdateHandlerReadsDeduplicatedCVEList(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "data", "tmp", "cve_data")
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cves.txt"), []byte("CVE-2024-3094\nnot-a-cve\nCVE-2024-3094\nCVE-2021-44228\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	repo := &vulnxRepositoryStub{existing: map[string]struct{}{"CVE-2021-44228": {}}}
	client := &vulnxClientStub{}
	handler := NewVulnxVulnerabilityUpdateHandler(root, vulnxTestJobs(nil), nil, nil, repo)
	handler.listFn = func(context.Context) ([]string, error) {
		return []string{"CVE-2024-3094", "not-a-cve", "CVE-2024-3094", "CVE-2021-44228"}, nil
	}
	handler.clientFn = func(string) *VulnxClient { return nil }
	handler.fetchFn = client.Fetch
	progress := &vulnxProgressStub{}
	if err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, progress); err != nil {
		t.Fatal(err)
	}
	gotIDs := append([]string(nil), client.ids...)
	sort.Strings(gotIDs)
	if len(gotIDs) != 1 || gotIDs[0] != "CVE-2024-3094" {
		t.Fatalf("fetched IDs = %v", gotIDs)
	}
	if progress.current != 1 || progress.total != 1 || len(repo.bundles) != 1 {
		t.Fatalf("progress = %d/%d, bundles = %d", progress.current, progress.total, len(repo.bundles))
	}
	if got, err := os.ReadFile(filepath.Join(path, "vulnXerror.txt")); err != nil || len(got) != 0 {
		t.Fatalf("error list = %q, err = %v", got, err)
	}
}

func TestVulnxUpdateHandlerRetriesAndWritesFinalFailures(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "data", "tmp", "cve_data")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cves.txt"), []byte("CVE-2024-0001\nCVE-2024-0002\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vulnXerror.txt"), []byte("CVE-OLD-STALE\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vulnXerrorDetail.log"), []byte("stale detail\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	client := &vulnxClientStub{failures: map[string]int{"CVE-2024-0001": vulnxRequestMaxAttempts, "CVE-2024-0002": 2 * vulnxRequestMaxAttempts}}
	repo := &vulnxRepositoryStub{}
	handler := NewVulnxVulnerabilityUpdateHandler(root, vulnxTestJobs(nil), nil, nil, repo)
	handler.listFn = func(context.Context) ([]string, error) { return []string{"CVE-2024-0001", "CVE-2024-0002"}, nil }
	handler.clientFn = func(string) *VulnxClient { return nil }
	handler.fetchFn = client.Fetch
	progress := &vulnxProgressStub{}
	err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, progress)
	if err == nil || !strings.Contains(err.Error(), "CVE-2024-0002") {
		t.Fatalf("Execute() error = %v", err)
	}
	var partial *vulnxPartialFailureError
	if !errors.As(err, &partial) || partial.count != 1 {
		t.Fatalf("Execute() partial failure = %v, want 1 failed CVE", err)
	}
	if got, want := len(client.ids), vulnxRequestMaxAttempts+1+2*vulnxRequestMaxAttempts; got != want {
		t.Fatalf("fetch calls = %d, want %d", got, want)
	}
	if progress.current != 2 || progress.total != 2 || len(repo.bundles) != 1 {
		t.Fatalf("progress = %d/%d, bundles = %d", progress.current, progress.total, len(repo.bundles))
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "vulnXerror.txt"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "CVE-2024-0002\n" {
		t.Fatalf("error list = %q", got)
	}
	detail, readErr := os.ReadFile(filepath.Join(dir, "vulnXerrorDetail.log"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(detail) != "CVE-2024-0002: temporary VulnX error\n" {
		t.Fatalf("error detail = %q", detail)
	}
}

func TestVulnxUpdateHandlerRemovesRecoveredFailuresAfterRetry(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "data", "tmp", "cve_data")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	client := &vulnxClientStub{failures: map[string]int{"CVE-2024-0001": vulnxRequestMaxAttempts}}
	handler := NewVulnxVulnerabilityUpdateHandler(root, vulnxTestJobs(nil), nil, nil, &vulnxRepositoryStub{})
	handler.listFn = func(context.Context) ([]string, error) { return []string{"CVE-2024-0001"}, nil }
	handler.clientFn = func(string) *VulnxClient { return nil }
	handler.fetchFn = client.Fetch
	if err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, &vulnxProgressStub{}); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got, want := len(client.ids), vulnxRequestMaxAttempts+1; got != want {
		t.Fatalf("fetch calls = %d, want %d", got, want)
	}
	for _, name := range []string{"vulnXerror.txt", "vulnXerrorDetail.log"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || len(data) != 0 {
			t.Fatalf("%s = %q, err = %v", name, data, err)
		}
	}
	archive, err := zip.OpenReader(filepath.Join(dir, "vulnXerror.zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	for _, file := range archive.File {
		content, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(content)
		closeErr := content.Close()
		if readErr != nil || closeErr != nil || len(data) != 0 {
			t.Fatalf("archive %s = %q, read err %v, close err %v", file.Name, data, readErr, closeErr)
		}
	}
}

func TestVulnxUpdateHandlerProcessesCVEsConcurrently(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "data", "tmp", "cve_data")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	var input strings.Builder
	for i := range vulnxRequestConcurrency {
		_, _ = fmt.Fprintf(&input, "CVE-2024-%04d\n", i+1)
	}
	if err := os.WriteFile(filepath.Join(dir, "cves.txt"), []byte(input.String()), 0o640); err != nil {
		t.Fatal(err)
	}
	var active, maxActive atomic.Int32
	allStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	handler := NewVulnxVulnerabilityUpdateHandler(root, vulnxTestJobs(nil), nil, nil, &vulnxRepositoryStub{})
	var names []string
	for i := range vulnxRequestConcurrency {
		names = append(names, fmt.Sprintf("CVE-2024-%04d", i+1))
	}
	handler.listFn = func(context.Context) ([]string, error) { return names, nil }
	handler.clientFn = func(string) *VulnxClient { return nil }
	handler.fetchFn = func(_ context.Context, id string) (*repository.VulnerabilityIntelligenceBundle, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for observed := maxActive.Load(); current > observed; observed = maxActive.Load() {
			if maxActive.CompareAndSwap(observed, current) {
				break
			}
		}
		if current == vulnxRequestConcurrency {
			once.Do(func() { close(allStarted) })
		}
		<-release
		return &repository.VulnerabilityIntelligenceBundle{Record: &entity.VulnerabilityIntelligenceRecord{Source: "vulnx", VulnerabilityID: id}}, nil
	}
	done := make(chan error, 1)
	go func() {
		done <- handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, nil)
	}()
	select {
	case <-allStarted:
	case err := <-done:
		t.Fatalf("Execute() returned before workers ran concurrently: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for concurrent workers")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := maxActive.Load(); got != vulnxRequestConcurrency {
		t.Fatalf("max concurrent requests = %d, want %d", got, vulnxRequestConcurrency)
	}
}

func TestVulnxUpdateHandlerValidatesEmptyConfig(t *testing.T) {
	handler := NewVulnxVulnerabilityUpdateHandler("", vulnxTestJobs(nil), nil, nil, &vulnxRepositoryStub{})
	if err := handler.Validate(json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := handler.Validate(json.RawMessage(`{"input_path":"/tmp/other"}`)); err == nil {
		t.Fatal("Validate() accepted unsupported config")
	}
	if err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{"}, entity.ScheduledJobRun{}, nil); err == nil {
		t.Fatal("Execute() accepted invalid config")
	}
}

func TestVulnxUpdateHandlerStopsOnContextCancellation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "data", "tmp", "cve_data")
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cves.txt"), []byte("CVE-2024-3094\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	handler := NewVulnxVulnerabilityUpdateHandler(root, vulnxTestJobs(nil), nil, nil, &vulnxRepositoryStub{})
	handler.listFn = func(context.Context) ([]string, error) { return []string{"CVE-2024-3094"}, nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handler.Execute(ctx, entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute() error = %v", err)
	}
}

var _ service.JobHandler = (*VulnxVulnerabilityUpdateHandler)(nil)
