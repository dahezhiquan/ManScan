package service

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/scanruntime"
)

func TestNormalizeCreateTaskRequestScreenshotSettings(t *testing.T) {
	t.Parallel()

	plan, err := normalizeCreateTaskRequest(dto.CreateScanTaskRequest{
		Targets:    []string{"https://example.com"},
		IncludeIDs: []string{"CVE-2026-0001", "screenshot", "SCREENSHOT"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Raw.ScreenshotCapture {
		t.Fatal("legacy screenshot template selection must enable screenshot_capture")
	}
	if !reflect.DeepEqual(plan.Raw.IncludeIDs, []string{"CVE-2026-0001"}) {
		t.Fatalf("IncludeIDs = %v", plan.Raw.IncludeIDs)
	}
	restored, err := normalizedTaskRequestFromTask(&entity.ScanTask{
		Targets:           `["https://example.com"]`,
		IncludeIDs:        `["screenshot","CVE-2026-0001"]`,
		ScreenshotCapture: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Raw.ScreenshotCapture {
		t.Fatalf("restored screenshot settings = capture:%v", restored.Raw.ScreenshotCapture)
	}
	if !reflect.DeepEqual(restored.Raw.IncludeIDs, []string{"CVE-2026-0001"}) {
		t.Fatalf("restored IncludeIDs = %v", restored.Raw.IncludeIDs)
	}
}

func TestNormalizeCreateTaskRequestRejectsScreenshotWithoutHTTPProbe(t *testing.T) {
	t.Parallel()

	for _, request := range []dto.CreateScanTaskRequest{
		{Targets: []string{"https://example.com"}, ScreenshotCapture: true, OfflineHTTP: true},
		{Targets: []string{"https://example.com"}, ScreenshotCapture: true, DisableHTTPProbe: true},
	} {
		if _, err := normalizeCreateTaskRequest(request); err == nil {
			t.Fatal("expected conflicting screenshot configuration to fail")
		}
	}
}

func TestUniqueAssetDomainScreenshotTargetsUsesNormalizedInput(t *testing.T) {
	t.Parallel()

	targets := uniqueAssetDomainScreenshotTargets([]assetDomainFingerprintTarget{
		{Input: " https://example.com/ ", Domain: "first.example.com"},
		{Input: "https://example.com", Domain: "second.example.com"},
		{Input: "https://other.example.com/", Domain: "other.example.com"},
	})
	if len(targets) != 2 || targets[0].Input != "https://example.com" || targets[1].Input != "https://other.example.com" {
		t.Fatalf("targets = %+v", targets)
	}
}

func TestScreenshotCapturePreservesScanStageOrder(t *testing.T) {
	for _, testCase := range []struct {
		name           string
		request        dto.CreateScanTaskRequest
		wantStages     []string
		mainScanIsAuto bool
		wantPlugins    int64
	}{
		{
			name:       "vulnerability template with active preflight",
			request:    dto.CreateScanTaskRequest{ScreenshotCapture: true, IncludeIDs: []string{"CVE-2026-0001"}},
			wantStages: []string{"active-fingerprint", "screenshot", "main-scan"},
		},
		{
			name: "screenshot only without active fingerprinting skips main scan",
			request: dto.CreateScanTaskRequest{
				ScreenshotCapture:    true,
				PreflightFingerprint: new(false),
			},
			wantStages:  []string{"screenshot"},
			wantPlugins: 1,
		},
		{
			name:        "screenshot only with active fingerprinting skips main scan",
			request:     dto.CreateScanTaskRequest{ScreenshotCapture: true},
			wantStages:  []string{"active-fingerprint", "screenshot"},
			wantPlugins: 1,
		},
		{
			name:           "automatic mapping remains enabled",
			request:        dto.CreateScanTaskRequest{ScreenshotCapture: true, AutomaticScan: true},
			wantStages:     []string{"screenshot", "main-auto-scan"},
			mainScanIsAuto: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rootDir := t.TempDir()
			stagesPath := filepath.Join(rootDir, "stages")
			script := "#!/bin/sh\n" +
				"previous=\n" +
				"for arg in \"$@\"; do\n" +
				"  if [ \"$arg\" = -silent ]; then echo screenshot >> " + stagesPath + "; exit 0; fi\n" +
				"  if [ \"$arg\" = --tags ]; then echo active-fingerprint >> " + stagesPath + "; exit 0; fi\n" +
				"  if [ \"$arg\" = -as ]; then previous=auto; fi\n" +
				"done\n" +
				"if [ \"$previous\" = auto ]; then echo main-auto-scan >> " + stagesPath + "; else echo main-scan >> " + stagesPath + "; fi\n"
			if err := os.WriteFile(filepath.Join(rootDir, "manscan"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "text/html")
				_, _ = writer.Write([]byte("<html><title>test</title></html>"))
			}))
			defer server.Close()

			state, err := scanruntime.NewState(251, "task-251", "screenshot-order", 1, filepath.Join(rootDir, "runtime"))
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			service := &scanTaskService{rootDir: rootDir, assetDomainRepository: &assetDomainRepositoryStub{}}
			runtime := newScanTaskRuntime(state)
			plan := &normalizedTaskRequest{Raw: testCase.request, CollectedTargets: []string{server.URL}}
			if err := service.executeTaskPlan(plan, runtime); err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(stagesPath)
			if err != nil {
				t.Fatal(err)
			}
			gotStages := strings.Fields(string(contents))
			if !reflect.DeepEqual(gotStages, testCase.wantStages) {
				t.Fatalf("stages = %v, want %v", gotStages, testCase.wantStages)
			}
			if got := state.SnapshotProgress().Templates; got != testCase.wantPlugins {
				t.Fatalf("plugin count = %d, want %d", got, testCase.wantPlugins)
			}
			if testCase.mainScanIsAuto && !hasArg(buildScanCLIArgs(testCase.request, "task", "targets.txt", "", "responses"), "-as") {
				t.Fatal("automatic mapping request lost the -as main scan option")
			}
		})
	}
}

func TestIsScreenshotOnlyTaskRequiresNoOtherTemplateSelection(t *testing.T) {
	t.Parallel()

	request := dto.CreateScanTaskRequest{
		ScreenshotCapture:    true,
		PreflightFingerprint: new(false),
	}
	if !isScreenshotOnlyTask(request) {
		t.Fatal("screenshot-only request should skip the main scan")
	}

	withSelection := []dto.CreateScanTaskRequest{
		{ScreenshotCapture: true, PreflightFingerprint: new(false), AutomaticScan: true},
		{ScreenshotCapture: true, PreflightFingerprint: new(false), IncludeIDs: []string{"CVE-2026-0001"}},
		{ScreenshotCapture: true, PreflightFingerprint: new(false), Tags: []string{"cve"}},
		{ScreenshotCapture: true, PreflightFingerprint: new(false), Severities: []string{"high"}},
		{ScreenshotCapture: true, PreflightFingerprint: new(false), Protocols: []string{"http"}},
		{ScreenshotCapture: true, PreflightFingerprint: new(false), DAST: true},
		{ScreenshotCapture: true, PreflightFingerprint: new(false), EnableCodeTemplates: true},
		{ScreenshotCapture: true, PreflightFingerprint: new(false), EnableFileTemplates: true},
		{ScreenshotCapture: true, PreflightFingerprint: new(false), EnableGlobalMatchersTemplates: true},
		{ScreenshotCapture: true, PreflightFingerprint: new(false), NewTemplates: true},
	}
	for _, candidate := range withSelection {
		if isScreenshotOnlyTask(candidate) {
			t.Fatalf("request should preserve main scan: %+v", candidate)
		}
	}
}

func TestScreenshotAndMainScanCLIArgsAreIsolated(t *testing.T) {
	t.Parallel()

	request := dto.CreateScanTaskRequest{
		AutomaticScan: true,
		Tags:          []string{"cve"},
		IncludeIDs:    []string{"CVE-2026-0001"},
		Severities:    []string{"high"},
		Protocols:     []string{"http"},
		Headless:      true,
	}
	mainArgs := buildScanCLIArgs(request, "task", "targets.txt", "", "responses")
	if got := flagValue(mainArgs, "-eid"); got != "screenshot" {
		t.Fatalf("main -eid = %q, args=%v", got, mainArgs)
	}
	if hasArg(mainArgs, "-ept") {
		t.Fatalf("removed headless exclusion option must not be passed: %v", mainArgs)
	}

	screenshotArgs := buildAssetDomainScreenshotCLIArgs(request, "task", "screenshots.txt")
	for _, required := range []string{"-id", "screenshot", "--headless"} {
		if !hasArg(screenshotArgs, required) {
			t.Fatalf("screenshot args missing %q: %v", required, screenshotArgs)
		}
	}
	for _, forbidden := range []string{"-as", "--tags", "-s", "-pt", "CVE-2026-0001", "cve", "high", "http"} {
		if hasArg(screenshotArgs, forbidden) {
			t.Fatalf("screenshot args contain main scan value %q: %v", forbidden, screenshotArgs)
		}
	}
}

func TestFinalizeScreenshotOutputsUsesTimestampAndTaskID(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	targets := []assetDomainFingerprintTarget{{Input: "https://app.example.com"}}
	legacyName := "https:__app.example.com_20261019.png"
	if err := os.WriteFile(filepath.Join(directory, legacyName), []byte("png"), 0o600); err != nil {
		t.Fatal(err)
	}
	succeeded, err := finalizeScreenshotOutputs(directory, targets, 42, time.Date(2026, 10, 19, 8, 9, 10, 0, time.Local))
	if err != nil {
		t.Fatal(err)
	}
	if succeeded != 1 {
		t.Fatalf("succeeded = %d", succeeded)
	}
	newPath := filepath.Join(directory, "https:__app.example.com_20261019-080910_42.png")
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("timestamped screenshot missing: %v", err)
	}
}
