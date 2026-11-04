package service

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/scanruntime"
)

func TestExecuteTaskPlanExcludesTargetsBeforeNetworkRequests(t *testing.T) {
	for _, testCase := range []struct {
		name           string
		screenshotOnly bool
		allExcluded    bool
	}{
		{name: "main scan all excluded", allExcluded: true},
		{name: "screenshot all excluded", screenshotOnly: true, allExcluded: true},
		{name: "main scan mixed targets"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var blockedRequests, allowedRequests atomic.Int64
			blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				blockedRequests.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer blocked.Close()
			allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				allowedRequests.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer allowed.Close()

			rootDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(rootDir, "manscan"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			state, err := scanruntime.NewState(432, "task-432", "excluded-preflight", 2, filepath.Join(rootDir, "runtime"))
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()

			disabled := false
			excludeRule := strings.TrimPrefix(blocked.URL, "http://")
			if testCase.allExcluded {
				excludeRule = "127.0.0.1"
			}
			request := dto.CreateScanTaskRequest{
				ExcludeTargets:       []string{excludeRule},
				PreflightFingerprint: &disabled,
				ProbeConcurrency:     1,
				Timeout:              3,
				ScreenshotCapture:    testCase.screenshotOnly,
			}
			targets := []string{blocked.URL, allowed.URL}
			service := &scanTaskService{rootDir: rootDir, assetDomainRepository: &assetDomainRepositoryStub{}}
			if err := service.executeTaskPlan(&normalizedTaskRequest{Raw: request, CollectedTargets: targets}, newScanTaskRuntime(state)); err != nil {
				t.Fatal(err)
			}
			if got := blockedRequests.Load(); got != 0 {
				t.Fatalf("excluded target received %d requests", got)
			}
			if testCase.allExcluded {
				if got := allowedRequests.Load(); got != 0 {
					t.Fatalf("second excluded target received %d requests", got)
				}
				if got := state.SnapshotProgress().Templates; got != 0 {
					t.Fatalf("plugin count = %d, want 0", got)
				}
				if _, err := os.Stat(filepath.Join(rootDir, "runtime", "432", "targets.txt")); !os.IsNotExist(err) {
					t.Fatalf("all-excluded task should not start main scan: %v", err)
				}
			} else {
				if got := allowedRequests.Load(); got == 0 {
					t.Fatal("allowed target was not probed")
				}
				contents, err := os.ReadFile(filepath.Join(filepath.Dir(state.LogFilePath), "targets.txt"))
				if err != nil {
					t.Fatal(err)
				}
				if strings.TrimSpace(string(contents)) != allowed.URL {
					t.Fatalf("main scan targets = %q, want only %q", contents, allowed.URL)
				}
			}
			foundExclusion := false
			for _, event := range state.EventsSince(0, 100).Events {
				if event.Type == "target_excluded" && strings.Contains(event.Message, request.ExcludeTargets[0]) {
					foundExclusion = true
				}
			}
			if !foundExclusion {
				t.Fatal("excluded target and matching rule were not logged")
			}
		})
	}
}
