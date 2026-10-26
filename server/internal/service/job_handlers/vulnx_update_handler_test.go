package job_handlers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"
)

type vulnxRepositoryStub struct {
	bundles []*repository.VulnerabilityIntelligenceBundle
	err     error
}

func (s *vulnxRepositoryStub) Replace(_ context.Context, bundle *repository.VulnerabilityIntelligenceBundle) error {
	if s.err != nil {
		return s.err
	}
	s.bundles = append(s.bundles, bundle)
	return nil
}

type vulnxClientStub struct {
	ids      []string
	failures map[string]int
}

func (c *vulnxClientStub) Fetch(_ context.Context, id string) (*repository.VulnerabilityIntelligenceBundle, error) {
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
	if got := len(client.ids); got != 2 || client.ids[0] != "CVE-2024-3094" || client.ids[1] != "CVE-2021-44228" {
		t.Fatalf("fetched IDs = %v", client.ids)
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
	client := &vulnxClientStub{failures: map[string]int{"CVE-2024-0001": 2, "CVE-2024-0002": vulnxRequestRetryCount + 1}}
	repo := &vulnxRepositoryStub{}
	handler := NewVulnxVulnerabilityUpdateHandler(root, nil, nil, repo)
	handler.clientFn = func(string) *VulnxClient { return nil }
	handler.fetchFn = client.Fetch
	progress := &vulnxProgressStub{}
	err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{}"}, entity.ScheduledJobRun{}, progress)
	if err == nil || !strings.Contains(err.Error(), "CVE-2024-0002") {
		t.Fatalf("Execute() error = %v", err)
	}
	if got, want := len(client.ids), (2+1)+(vulnxRequestRetryCount+1); got != want {
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
