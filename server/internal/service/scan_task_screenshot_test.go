package service

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
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
	if plan.Raw.DisableHeadlessTemplates == nil || !*plan.Raw.DisableHeadlessTemplates {
		t.Fatal("disable_headless_templates must default to true")
	}

	enabled := false
	plan, err = normalizeCreateTaskRequest(dto.CreateScanTaskRequest{
		Targets:                  []string{"https://example.com"},
		DisableHeadlessTemplates: &enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Raw.DisableHeadlessTemplates == nil || *plan.Raw.DisableHeadlessTemplates {
		t.Fatal("explicit false must be retained")
	}
	restored, err := normalizedTaskRequestFromTask(&entity.ScanTask{
		Targets:                  `["https://example.com"]`,
		IncludeIDs:               `["screenshot","CVE-2026-0001"]`,
		ScreenshotCapture:        false,
		DisableHeadlessTemplates: &enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Raw.ScreenshotCapture || restored.Raw.DisableHeadlessTemplates == nil || *restored.Raw.DisableHeadlessTemplates {
		t.Fatalf("restored screenshot settings = capture:%v disable_headless:%v", restored.Raw.ScreenshotCapture, restored.Raw.DisableHeadlessTemplates)
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

func TestScreenshotAndMainScanCLIArgsAreIsolated(t *testing.T) {
	t.Parallel()

	disabled := true
	request := dto.CreateScanTaskRequest{
		AutomaticScan:            true,
		Tags:                     []string{"cve"},
		IncludeIDs:               []string{"CVE-2026-0001"},
		Severities:               []string{"high"},
		Protocols:                []string{"http"},
		Headless:                 true,
		DisableHeadlessTemplates: &disabled,
	}
	mainArgs := buildScanCLIArgs(request, "task", "targets.txt", "", "responses")
	if got := flagValue(mainArgs, "-eid"); got != "screenshot" {
		t.Fatalf("main -eid = %q, args=%v", got, mainArgs)
	}
	if got := flagValue(mainArgs, "-ept"); got != "headless" {
		t.Fatalf("main -ept = %q, args=%v", got, mainArgs)
	}
	allowHeadless := false
	request.DisableHeadlessTemplates = &allowHeadless
	mainArgs = buildScanCLIArgs(request, "task", "targets.txt", "", "responses")
	if hasArg(mainArgs, "-ept") || flagValue(mainArgs, "-eid") != "screenshot" {
		t.Fatalf("explicitly enabled headless must only exclude screenshot: %v", mainArgs)
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
