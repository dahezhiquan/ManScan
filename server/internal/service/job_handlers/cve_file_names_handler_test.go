package job_handlers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ManScan/server/internal/model/entity"
)

func TestWriteCVEFileNamesReplacesOutputAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data", "tmp", "cve_data", "cves.txt")
	if err := writeCVEFileNames(path, []string{"CVE-2024-0002", "CVE-2024-0001"}, nil, context.Background()); err != nil {
		t.Fatalf("writeCVEFileNames() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if got, want := string(content), "CVE-2024-0002\nCVE-2024-0001\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read output directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".cves-") {
			t.Fatalf("temporary file %q was not removed", entry.Name())
		}
	}
}

func TestCVEFileNamesHandlerValidate(t *testing.T) {
	handler := NewCVEFileNamesHandler(t.TempDir(), nil)
	if err := handler.Validate([]byte(`{"ref":"main"}`)); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if err := handler.Validate([]byte(`{"ref":"bad\nref"}`)); err == nil {
		t.Fatal("Validate() accepted a ref containing a newline")
	}
	if err := handler.Execute(context.Background(), entity.ScheduledJob{ConfigJSON: "{"}, entity.ScheduledJobRun{}, nil); err == nil {
		t.Fatal("Execute() accepted invalid JSON")
	}
}
