package job_handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"
)

type vulnxRepositoryStub struct {
	mu      sync.Mutex
	bundles []*repository.VulnerabilityIntelligenceBundle
	err     error
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
	return nil
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

func (p *vulnxProgressStub) Report(_ context.Context, current, total int64, _, _ string) error {
	p.current, p.total = current, total
	return nil
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
	repo := &vulnxRepositoryStub{}
	client := &vulnxClientStub{}
	handler := NewVulnxVulnerabilityUpdateHandler(root, nil, nil, repo)
	handler.clientFn = func(string) *VulnxClient { return nil }
	handler.fetchFn = client.Fetch
	progress := &vulnxProgressStub{}
	if err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, progress); err != nil {
		t.Fatal(err)
	}
	gotIDs := append([]string(nil), client.ids...)
	sort.Strings(gotIDs)
	if len(gotIDs) != 2 || gotIDs[0] != "CVE-2021-44228" || gotIDs[1] != "CVE-2024-3094" {
		t.Fatalf("fetched IDs = %v", gotIDs)
	}
	if progress.current != 2 || progress.total != 2 || len(repo.bundles) != 2 {
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
	client := &vulnxClientStub{failures: map[string]int{"CVE-2024-0001": 2, "CVE-2024-0002": vulnxRequestMaxAttempts}}
	repo := &vulnxRepositoryStub{}
	handler := NewVulnxVulnerabilityUpdateHandler(root, nil, nil, repo)
	handler.clientFn = func(string) *VulnxClient { return nil }
	handler.fetchFn = client.Fetch
	progress := &vulnxProgressStub{}
	err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, progress)
	if err == nil || !strings.Contains(err.Error(), "CVE-2024-0002") {
		t.Fatalf("Execute() error = %v", err)
	}
	if got, want := len(client.ids), (2+1)+vulnxRequestMaxAttempts; got != want {
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
	handler := NewVulnxVulnerabilityUpdateHandler(root, nil, nil, &vulnxRepositoryStub{})
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
	handler := NewVulnxVulnerabilityUpdateHandler("", nil, nil, &vulnxRepositoryStub{})
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
	handler := NewVulnxVulnerabilityUpdateHandler(root, nil, nil, &vulnxRepositoryStub{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handler.Execute(ctx, entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute() error = %v", err)
	}
}

var _ service.JobHandler = (*VulnxVulnerabilityUpdateHandler)(nil)
