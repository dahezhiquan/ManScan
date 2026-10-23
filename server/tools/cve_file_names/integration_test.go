package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// TestFetchAllCVEFileNames requests the real GitHub API and exports cve.txt.
// Opt in explicitly so normal unit tests do not require internet access.
func TestFetchAllCVEFileNames(t *testing.T) {
	if os.Getenv("CVE_INTEGRATION_TEST") != "1" {
		t.Skip("set CVE_INTEGRATION_TEST=1 to fetch the full list from GitHub")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	started := time.Now()
	names, err := NewGitHubTreeClient(os.Getenv("GITHUB_TOKEN")).ListCVEFileNames(ctx, "main")
	if err != nil {
		t.Fatalf("fetch full CVE list: %v", err)
	}
	fetchDuration := time.Since(started)
	if len(names) == 0 || !sort.StringsAreSorted(names) {
		t.Fatal("expected a nonempty, sorted CVE list")
	}
	for i, name := range names {
		if !cveFileNamePattern.MatchString(name + ".json") {
			t.Fatalf("invalid CVE name: %q", name)
		}
		if i > 0 && names[i-1] == name {
			t.Fatalf("duplicate CVE name: %q", name)
		}
	}

	// Go runs this package's tests from server/tools/cve_file_names.
	outputPath, err := filepath.Abs(filepath.Join("..", "..", "..", "cve.txt"))
	if err != nil {
		t.Fatalf("resolve output path: %v", err)
	}
	file, err := os.CreateTemp(filepath.Dir(outputPath), ".cve-*.tmp")
	if err != nil {
		t.Fatalf("create temporary output: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(file.Name()); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove temporary output: %v", err)
		}
	})
	closed := false
	defer func() {
		if !closed {
			if err := file.Close(); err != nil {
				t.Errorf("close temporary output: %v", err)
			}
		}
	}()
	writer := bufio.NewWriter(file)
	for _, name := range names {
		if _, err := fmt.Fprintln(writer, name); err != nil {
			t.Fatalf("write CVE name: %v", err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("flush CVE names: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close CVE output: %v", err)
	}
	closed = true
	if err := os.Rename(file.Name(), outputPath); err != nil {
		t.Fatalf("publish CVE output: %v", err)
	}
	t.Logf("CVE count: %d; fetch duration: %s; total duration: %s; output: %s",
		len(names), fetchDuration.Round(time.Millisecond), time.Since(started).Round(time.Millisecond), outputPath)
}
