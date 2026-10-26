package job_handlers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"
)

type vulnxRepositoryStub struct {
	bundles []*repository.VulnerabilityIntelligenceBundle
}

func (s *vulnxRepositoryStub) Replace(_ context.Context, bundle *repository.VulnerabilityIntelligenceBundle) error {
	s.bundles = append(s.bundles, bundle)
	return nil
}

type vulnxClientStub struct {
	ids []string
}

func (c *vulnxClientStub) Fetch(_ context.Context, id string) (*repository.VulnerabilityIntelligenceBundle, error) {
	c.ids = append(c.ids, id)
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
