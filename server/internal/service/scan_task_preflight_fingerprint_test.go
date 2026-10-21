package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/scanruntime"
)

func TestNormalizePreflightFingerprint(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		body string
		want bool
	}{
		{name: "omitted", body: `{}`, want: true},
		{name: "null", body: `{"preflight_fingerprint":null}`, want: true},
		{name: "enabled", body: `{"preflight_fingerprint":true}`, want: true},
		{name: "disabled", body: `{"preflight_fingerprint":false}`, want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var request dto.CreateScanTaskRequest
			if err := json.Unmarshal([]byte(testCase.body), &request); err != nil {
				t.Fatal(err)
			}
			request.Targets = []string{"https://example.com"}
			plan, err := normalizeCreateTaskRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Raw.PreflightFingerprint == nil || *plan.Raw.PreflightFingerprint != testCase.want {
				t.Fatalf("PreflightFingerprint = %v, want %v", plan.Raw.PreflightFingerprint, testCase.want)
			}
			restored, err := normalizedTaskRequestFromTask(&entity.ScanTask{
				Targets:              `["https://example.com"]`,
				PreflightFingerprint: plan.Raw.PreflightFingerprint,
			})
			if err != nil {
				t.Fatal(err)
			}
			if restored.Raw.PreflightFingerprint == nil || *restored.Raw.PreflightFingerprint != testCase.want {
				t.Fatalf("restored PreflightFingerprint = %v, want %v", restored.Raw.PreflightFingerprint, testCase.want)
			}
		})
	}
	legacyPlan, err := normalizedTaskRequestFromTask(&entity.ScanTask{Targets: `["https://example.com"]`})
	if err != nil {
		t.Fatal(err)
	}
	if legacyPlan.Raw.PreflightFingerprint == nil || !*legacyPlan.Raw.PreflightFingerprint {
		t.Fatal("legacy tasks must default to enabled")
	}
}

func TestPreflightFingerprintControlsMainScanFingerprintExclusion(t *testing.T) {
	t.Parallel()

	service := &scanTaskService{assetDomainRepository: &assetDomainRepositoryStub{}}
	for _, automaticScan := range []bool{false, true} {
		request := dto.CreateScanTaskRequest{AutomaticScan: automaticScan, IncludeIDs: []string{"selected-fingerprint-template"}}
		buildArgs := func() []string {
			return buildScanCLIArgs(request, "task", "targets.txt", "resume.cfg", "responses", service.shouldExcludeAssetDomainFingerprintTemplates(request, []string{"https://example.com"}))
		}
		defaultArgs := buildArgs()
		if automaticScan {
			if !hasArg(defaultArgs, "-as") || hasArg(defaultArgs, "-etags") {
				t.Fatalf("automatic mapping must keep detection templates: %v", defaultArgs)
			}
		} else if flagValue(defaultArgs, "-etags") != "tech,detect,favicon" {
			t.Fatalf("enabled preflight fingerprinting must exclude duplicate fingerprint templates: %v", defaultArgs)
		}

		disabled := false
		request.PreflightFingerprint = &disabled
		disabledArgs := buildArgs()
		if flagValue(disabledArgs, "-id") != "selected-fingerprint-template" {
			t.Fatalf("selected fingerprint template must remain in the main scan: %v", disabledArgs)
		}
		if automaticScan {
			if !hasArg(disabledArgs, "-as") || hasArg(disabledArgs, "-etags") {
				t.Fatalf("automatic mapping must keep detection templates when preflight fingerprinting is disabled: %v", disabledArgs)
			}
		} else if hasArg(disabledArgs, "-etags") {
			t.Fatalf("disabled preflight fingerprinting must keep selected fingerprint templates in the main scan: %v", disabledArgs)
		}
	}
}

func TestDisabledPreflightFingerprintKeepsPassiveProbeAndCache(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.Header().Set("Server", "nginx/1.24.0")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	taskDir := t.TempDir()
	fingerprintCachePath := filepath.Join(taskDir, "asset-domain-fingerprints.json")
	preflightCachePath := filepath.Join(taskDir, "asset-domain-preflight.json")
	repo := &assetDomainRepositoryStub{}
	hostPortRepo := &assetHostPortRepositoryStub{}
	service := &scanTaskService{
		assetDomainRepository:   repo,
		assetHostPortRepository: hostPortRepo,
		rootDir:                 taskDir,
	}
	state := &scanruntime.State{}
	queue := newAssetDomainServiceAssetQueue(service, state)
	defer queue.CloseAndWait()
	disabled := false
	request := dto.CreateScanTaskRequest{PreflightFingerprint: &disabled, ProbeConcurrency: 1, Timeout: 3}

	if err := service.syncAliveAssetDomainsBeforeScan(context.Background(), request, []string{server.URL}, state, fingerprintCachePath, preflightCachePath, queue, nil); err != nil {
		t.Fatal(err)
	}
	if requests.Load() == 0 || len(repo.syncObservationValues) != 1 || len(repo.syncObservationValues[0]) != 1 {
		t.Fatal("disabled active fingerprinting must still probe liveness")
	}
	cache, err := readAssetDomainPreflightCache(preflightCachePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cache.Targets) != 1 || !cache.Targets[0].ProbeDone || !cache.Targets[0].WappalyzerDone || cache.Targets[0].ActiveFingerprintDone {
		t.Fatalf("unexpected preflight cache: %+v", cache.Targets)
	}
	foundNginx := false
	for _, component := range cache.Targets[0].WappalyzerServiceAssets {
		if strings.EqualFold(component.AppName, "nginx") {
			foundNginx = true
		}
	}
	if !foundNginx {
		t.Fatalf("Wappalyzer components missing nginx: %+v", cache.Targets[0].WappalyzerServiceAssets)
	}
	if _, err := os.Stat(fingerprintCachePath); err != nil {
		t.Fatalf("passive fingerprint cache missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(taskDir, "asset-domain-fingerprint-targets.txt")); !os.IsNotExist(err) {
		t.Fatalf("active fingerprint targets must not be written: %v", err)
	}
	activeTargets, unresponsiveTargets := cache.pendingFingerprintTargets(request, []string{server.URL})
	if len(activeTargets) != 0 || len(unresponsiveTargets) != 0 {
		t.Fatal("disabled fingerprinting must not schedule HTTP or non-HTTP active probes")
	}
	if queue.FingerprintStaleSyncEnabled() {
		t.Fatal("disabled active fingerprinting must not mark missing domain or host fingerprints inactive")
	}
	queue.CloseAndWait()
	repo.syncServiceAssetObservations = nil
	repo.syncServiceAssetCheckedDomains = nil
	hostPortRepo.observationValues = nil
	service.syncFinishedAssetHostHTTPPorts(queue, state)
	service.syncFinishedAssetDomainServiceAssets(queue, state)
	if len(hostPortRepo.inactiveObservationValues) != 0 {
		t.Fatalf("host port stale syncs = %+v, want none without active fingerprinting", hostPortRepo.inactiveObservationValues)
	}
	if len(repo.syncServiceAssetCheckedDomains) != 1 || len(repo.syncServiceAssetCheckedDomains[0]) != 0 {
		t.Fatalf("service asset checked domains = %+v, want empty stale scope without active fingerprinting", repo.syncServiceAssetCheckedDomains)
	}
	if len(repo.syncServiceAssetObservations) != 1 || len(repo.syncServiceAssetObservations[0]) == 0 {
		t.Fatalf("service asset observations = %+v, want current passive fingerprints retained", repo.syncServiceAssetObservations)
	}
	beforeReuse := requests.Load()
	if err := service.syncAliveAssetDomainsBeforeScan(context.Background(), request, []string{server.URL}, state, fingerprintCachePath, preflightCachePath, nil, nil); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != beforeReuse {
		t.Fatal("passive-only preflight cache must be reusable without repeated HTTP requests")
	}
	completed, pending := cache.splitCompletedTargets([]string{server.URL}, dto.CreateScanTaskRequest{})
	if len(pending) != 1 || len(completed.CheckedDomains) != 0 {
		t.Fatal("enabled manual scan must still require active fingerprinting")
	}
	completed, pending = cache.splitCompletedTargets([]string{server.URL}, dto.CreateScanTaskRequest{AutomaticScan: true, PreflightFingerprint: &disabled})
	if len(pending) != 0 || len(completed.ServiceAssets) == 0 || len(completed.Fingerprints) == 0 {
		t.Fatal("automatic mapping must still reuse passive fingerprints")
	}
}
