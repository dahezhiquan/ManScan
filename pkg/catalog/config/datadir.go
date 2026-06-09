package config

import (
	"os"
	"path/filepath"
	"sync"
)

var (
	repoRootOnce sync.Once
	repoRootPath string
)

// RepoRootDir returns the repository root directory if it can be discovered.
// It falls back to the current working directory when discovery fails.
func RepoRootDir() string {
	repoRootOnce.Do(func() {
		repoRootPath = discoverRepoRoot()
	})
	return repoRootPath
}

func discoverRepoRoot() string {
	if value := os.Getenv("MANSCAN_DATA_ROOT"); value != "" {
		if abs, err := filepath.Abs(value); err == nil {
			return filepath.Clean(abs)
		}
		return filepath.Clean(value)
	}

	wd, err := os.Getwd()
	if err != nil || wd == "" {
		return "."
	}
	wd, _ = filepath.Abs(wd)
	current := wd
	for {
		if fileExists(filepath.Join(current, "go.mod")) && fileExists(filepath.Join(current, "AGENTS.md")) {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return wd
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// DefaultDataRoot returns the root data directory within the repository.
func DefaultDataRoot() string {
	return filepath.Join(RepoRootDir(), "data")
}

// DefaultDataSubdir returns an absolute path for a managed data subdirectory.
func DefaultDataSubdir(name string) string {
	return filepath.Join(DefaultDataRoot(), name)
}

// DefaultDataFile returns an absolute path within a managed data subdirectory.
func DefaultDataFile(dir, name string) string {
	return filepath.Join(DefaultDataSubdir(dir), name)
}

func DefaultConfigDir() string {
	return DefaultDataSubdir("config")
}

func DefaultCacheDir() string {
	return DefaultDataSubdir("cache")
}

func DefaultTemplatesDir() string {
	return DefaultDataSubdir("templates")
}

func DefaultResponsesDir() string {
	return DefaultDataSubdir("responses")
}

func DefaultProjectDir() string {
	return DefaultDataSubdir("project")
}

func DefaultStatsDir() string {
	return DefaultDataSubdir("stats")
}

func DefaultRuntimeTmpDir() string {
	return DefaultDataSubdir(filepath.Join("tmp", "runtime"))
}

func DefaultSecretsTmpDir() string {
	return DefaultDataSubdir(filepath.Join("tmp", "secrets"))
}

func DefaultHeadlessTmpDir() string {
	return DefaultDataSubdir(filepath.Join("tmp", "headless"))
}

func DefaultReportsDir() string {
	return DefaultDataSubdir("reports")
}

func DefaultMarkdownReportsDir() string {
	return DefaultDataSubdir(filepath.Join("reports", "markdown"))
}

func DefaultJSONReportPath() string {
	return DefaultDataFile(filepath.Join("reports", "json"), "nuclei-report.json")
}

func DefaultJSONLReportPath() string {
	return DefaultDataFile(filepath.Join("reports", "jsonl"), "nuclei-report.jsonl")
}

func DefaultSARIFReportPath() string {
	return DefaultDataFile(filepath.Join("reports", "sarif"), "nuclei-report.sarif")
}

func DefaultPDFReportPath() string {
	return DefaultDataFile(filepath.Join("reports", "pdf"), "nuclei-report.pdf")
}

func DefaultReportingDBPath() string {
	return DefaultDataSubdir(filepath.Join("cache", "reporting", "leveldb"))
}

func DefaultResumeDir() string {
	return DefaultDataSubdir(filepath.Join("cache", "resume"))
}

func DefaultCrashDir() string {
	return DefaultDataSubdir(filepath.Join("cache", "crash"))
}
