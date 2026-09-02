package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/pkg/scanruntime"

	"gorm.io/gorm"
)

func TestCollectTargetsNormalizesTrailingSlash(t *testing.T) {
	t.Parallel()

	targets := collectTargets(
		[]string{
			" http://10.107.71.65:8889/ ",
			"http://10.107.71.65:8889",
			"https://example.com/api/",
			"demo.example.com/",
		},
		"http://10.107.71.65:8889/\nhttps://example.com/api/\n\n",
	)

	expected := []string{
		"http://10.107.71.65:8889",
		"https://example.com/api",
		"demo.example.com",
	}
	if len(targets) != len(expected) {
		t.Fatalf("target count = %d, want %d (%v)", len(targets), len(expected), targets)
	}
	for index, want := range expected {
		if targets[index] != want {
			t.Fatalf("targets[%d] = %q, want %q (all=%v)", index, targets[index], want, targets)
		}
	}
}

func TestToScanTaskSummaryIncludesResultStats(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, 8, 24, 10, 0, 0, 0, time.FixedZone("CST", 8*3600))
	finishedAt := startedAt.Add(5 * time.Minute)
	task := &entity.ScanTask{
		ID:          27,
		TaskNo:      "task-27",
		Name:        "demo-task",
		Status:      "success",
		CreatedBy:   "tester",
		StartedAt:   &startedAt,
		FinishedAt:  &finishedAt,
		Description: ptr("task desc"),
	}
	result := &entity.ScanTaskResult{
		CriticalCount: 1,
		HighCount:     2,
		MediumCount:   3,
		LowCount:      4,
		InfoCount:     5,
		TechCount:     6,
		PluginCount:   7,
		TargetCount:   8,
		TotalRequests: 9,
		RealRequests:  10,
	}

	summary := toScanTaskSummary(task, result)
	if summary.TechCount != 6 {
		t.Fatalf("TechCount = %d, want 6", summary.TechCount)
	}
	if summary.InfoCount != 5 || summary.HighCount != 2 || summary.PluginCount != 7 || summary.TargetCount != 8 {
		t.Fatalf("unexpected summary stats: %+v", summary)
	}
}

func TestToScanTaskSummaryWithoutResultStats(t *testing.T) {
	t.Parallel()

	task := &entity.ScanTask{
		ID:        28,
		TaskNo:    "task-28",
		Name:      "demo-task-2",
		Status:    "running",
		CreatedBy: "tester",
	}

	summary := toScanTaskSummary(task, nil)
	if summary.TechCount != 0 || summary.InfoCount != 0 || summary.PluginCount != 0 {
		t.Fatalf("expected zero-value stats when result is nil: %+v", summary)
	}
}

func TestToScanTaskResultIncludesRequestStats(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, 8, 25, 10, 0, 0, 0, time.FixedZone("CST", 8*3600))
	finishedAt := startedAt.Add(3 * time.Minute)
	summary := scanruntime.ResultSummary{
		CriticalCount: 1,
		HighCount:     2,
		MediumCount:   3,
		LowCount:      4,
		InfoCount:     5,
		TechCount:     6,
		PluginCount:   7,
		TargetCount:   8,
		TotalRequests: 9,
		RealRequests:  10,
	}

	result := toScanTaskResult(11, "demo-task", &startedAt, finishedAt, summary)
	if result.TotalRequests != 9 || result.RealRequests != 10 {
		t.Fatalf("unexpected request stats: %+v", result)
	}
}

func TestResultHandlerUpsertsVulnerabilityWithTemplateDetail(t *testing.T) {
	t.Parallel()

	foundAt := time.Date(2026, 8, 27, 12, 30, 0, 0, time.UTC)
	vulnerabilityRepo := &vulnerabilityRepositoryStub{}
	svc := &scanTaskService{
		vulnerabilityRepository: vulnerabilityRepo,
		templateRepository: &templateRepositoryStub{
			details: map[string]*dto.TemplateDetail{
				"CVE-2026-0001": {
					ID:          "CVE-2026-0001",
					Name:        "HTTP 安全响应头缺失",
					Protocols:   []string{"http"},
					Tags:        []string{"cve", "kev"},
					Severity:    "high",
					Description: "模板描述",
					Impact:      "模板影响",
					Remediation: "模板修复建议",
					Reference:   []string{"https://example.com/advisory"},
					CVSSScore:   8.8,
					Vendor:      "demo-vendor",
					Product:     "demo-product",
				},
			},
		},
	}

	queue := newVulnerabilityQueue(svc)
	handler := svc.resultHandler(42, "即时扫描任务", queue)
	handler(map[string]interface{}{
		"template-id":   "CVE-2026-0001",
		"matched-at":    "https://app.example.com:8443/login",
		"host":          "app.example.com",
		"ip":            "192.0.2.10",
		"port":          "8443",
		"type":          "http",
		"matcher-name":  "cross-origin-embedder-policy",
		"request":       `{"1":"GET /login HTTP/1.1\r\nHost: app.example.com\r\n\r\n","2":"POST /login HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 7\r\n\r\npayload"}`,
		"response":      `{"1":"HTTP/1.1 200 OK\r\n\r\nfirst","2":"HTTP/1.1 500 Internal Server Error\r\n\r\nsecond"}`,
		"curl-command":  "curl -k https://app.example.com:8443/login",
		"template-path": "/tmp/template.yaml",
		"timestamp":     foundAt.Format(time.RFC3339Nano),
		"info": map[string]interface{}{
			"name":     "result name should not win",
			"severity": "low",
		},
	})
	queue.CloseAndWait()

	if len(vulnerabilityRepo.items) != 1 {
		t.Fatalf("upserted vulnerabilities = %d, want 1", len(vulnerabilityRepo.items))
	}
	if vulnerabilityRepo.batchCalls != 1 {
		t.Fatalf("batch upsert calls = %d, want 1", vulnerabilityRepo.batchCalls)
	}
	got := vulnerabilityRepo.items[0]
	if got.Severity != "high" {
		t.Fatalf("template detail was not reused: %+v", got)
	}
	if got.VulnerabilityName != "HTTP 安全响应头缺失 - cross-origin-embedder-policy" {
		t.Fatalf("VulnerabilityName = %q, want %q", got.VulnerabilityName, "HTTP 安全响应头缺失 - cross-origin-embedder-policy")
	}
	if got.AssetDomain == nil || *got.AssetDomain != "https://app.example.com:8443/login" {
		t.Fatalf("AssetDomain = %v, want https://app.example.com:8443/login", got.AssetDomain)
	}
	if got.AssetHost == nil || *got.AssetHost != "192.0.2.10" {
		t.Fatalf("AssetHost = %v, want 192.0.2.10", got.AssetHost)
	}
	if got.AssetPort == nil || *got.AssetPort != 8443 {
		t.Fatalf("AssetPort = %v, want 8443", got.AssetPort)
	}
	if got.FirstFoundAt != foundAt || got.LastFoundAt != foundAt {
		t.Fatalf("found time = %s/%s, want %s", got.FirstFoundAt, got.LastFoundAt, foundAt)
	}
	wantFingerprint := buildVulnerabilityFingerprint("CVE-2026-0001", "192.0.2.10", 8443, "http", "/login|cross-origin-embedder-policy")
	if got.VulnFingerprint != wantFingerprint {
		t.Fatalf("VulnFingerprint = %q, want %q", got.VulnFingerprint, wantFingerprint)
	}

	var tags []string
	if got.Tags == nil || json.Unmarshal([]byte(*got.Tags), &tags) != nil || len(tags) != 2 || tags[0] != "cve" || tags[1] != "kev" {
		t.Fatalf("Tags = %v, want JSON tags", got.Tags)
	}
	if got.Detail == nil {
		t.Fatal("Detail = nil, want JSON object")
	}
	var detail map[string]interface{}
	if err := json.Unmarshal([]byte(*got.Detail), &detail); err != nil {
		t.Fatalf("unmarshal Detail failed: %v", err)
	}
	requestHistory, ok := detail["request"].(map[string]interface{})
	if !ok {
		t.Fatalf("Detail request = %#v, want object", detail["request"])
	}
	if _, ok := requestHistory["1"]; !ok {
		t.Fatal("Detail request missing 1")
	}
	if _, ok := requestHistory["2"]; !ok {
		t.Fatal("Detail request missing 2")
	}
	responseHistory, ok := detail["response"].(map[string]interface{})
	if !ok {
		t.Fatalf("Detail response = %#v, want object", detail["response"])
	}
	if _, ok := responseHistory["1"]; !ok {
		t.Fatal("Detail response missing 1")
	}
	if _, ok := responseHistory["2"]; !ok {
		t.Fatal("Detail response missing 2")
	}
	if _, ok := detail["request"]; !ok {
		t.Fatal("Detail missing request")
	}
	if _, ok := detail["response"]; !ok {
		t.Fatal("Detail missing response")
	}
	if _, ok := detail["curl-command"]; !ok {
		t.Fatal("Detail missing curl-command")
	}
	if _, ok := detail["request1"]; ok {
		t.Fatal("Detail unexpectedly contains request1")
	}
	if _, ok := detail["request2"]; ok {
		t.Fatal("Detail unexpectedly contains request2")
	}
	if _, ok := detail["response1"]; ok {
		t.Fatal("Detail unexpectedly contains response1")
	}
	if _, ok := detail["response2"]; ok {
		t.Fatal("Detail unexpectedly contains response2")
	}
	if _, ok := detail["template-path"]; ok {
		t.Fatal("Detail unexpectedly contains template-path")
	}
}

func TestBuildVulnerabilitySkipsTechTagResult(t *testing.T) {
	t.Parallel()

	svc := &scanTaskService{
		templateRepository: &templateRepositoryStub{
			details: map[string]*dto.TemplateDetail{
				"nginx-detect": {
					ID:       "nginx-detect",
					Name:     "Nginx Detect",
					Tags:     []string{"web", "tech"},
					Severity: "info",
				},
			},
		},
	}

	vulnerability, err := svc.buildVulnerabilityFromPayload(context.Background(), 42, "即时扫描任务", map[string]interface{}{
		"template-id": "nginx-detect",
		"matched-at":  "https://app.example.com/",
		"info": map[string]interface{}{
			"name":     "Nginx Detect",
			"severity": "info",
			"tags":     []interface{}{"web", "tech"},
		},
	})
	if err != nil {
		t.Fatalf("buildVulnerabilityFromPayload() error = %v", err)
	}
	if vulnerability != nil {
		t.Fatalf("vulnerability = %+v, want nil for tech tag result", vulnerability)
	}
}

func TestBuildVulnerabilityDoesNotSkipFingerprintNameWithoutTechTag(t *testing.T) {
	t.Parallel()

	svc := &scanTaskService{
		templateRepository: &templateRepositoryStub{
			details: map[string]*dto.TemplateDetail{
				"legacy-fingerprint": {
					ID:       "legacy-fingerprint",
					Name:     "Nginx 指纹识别",
					Tags:     []string{"web"},
					Severity: "info",
				},
			},
		},
	}

	vulnerability, err := svc.buildVulnerabilityFromPayload(context.Background(), 42, "即时扫描任务", map[string]interface{}{
		"template-id": "legacy-fingerprint",
		"matched-at":  "https://app.example.com/",
		"info": map[string]interface{}{
			"name":     "Nginx 指纹识别",
			"severity": "info",
			"tags":     []interface{}{"web"},
		},
	})
	if err != nil {
		t.Fatalf("buildVulnerabilityFromPayload() error = %v", err)
	}
	if vulnerability == nil {
		t.Fatal("vulnerability = nil, want item when tech tag is absent")
	}
	if vulnerability.VulnerabilityName != "Nginx 指纹识别" {
		t.Fatalf("VulnerabilityName = %q, want Nginx 指纹识别", vulnerability.VulnerabilityName)
	}
}

func TestBuildVulnerabilityNormalizesProtocol(t *testing.T) {
	t.Parallel()

	svc := &scanTaskService{
		templateRepository: &templateRepositoryStub{},
	}

	vulnerability, err := svc.buildVulnerabilityFromPayload(context.Background(), 42, "即时扫描任务", map[string]interface{}{
		"template-id": "tcp-detect",
		"matched-at":  "10.0.0.1:6379",
		"type":        "network",
		"timestamp":   time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		"info": map[string]interface{}{
			"name":     "TCP Detect",
			"severity": "low",
		},
	})
	if err != nil {
		t.Fatalf("buildVulnerabilityFromPayload() error = %v", err)
	}
	if vulnerability == nil || vulnerability.Protocol == nil || *vulnerability.Protocol != "tcp" {
		t.Fatalf("Protocol = %v, want tcp", vulnerability)
	}
}

func TestApplyRuntimeResultSummaryToListItem(t *testing.T) {
	t.Parallel()

	item := &dto.ScanTaskListItem{}
	applyRuntimeResultSummaryToListItem(item, scanruntime.ResultSummary{
		CriticalCount: 1,
		HighCount:     2,
		MediumCount:   3,
		LowCount:      4,
		InfoCount:     5,
		TechCount:     6,
		PluginCount:   7,
		TargetCount:   8,
		TotalRequests: 9,
		RealRequests:  10,
	})

	if item.CriticalCount != 1 || item.PluginCount != 7 || item.TotalRequests != 9 || item.RealRequests != 10 {
		t.Fatalf("unexpected list item stats: %+v", item)
	}
}

func TestApplyProgressSnapshotToListItem(t *testing.T) {
	t.Parallel()

	item := &dto.ScanTaskListItem{}
	applyProgressSnapshotToListItem(item, scanruntime.TaskProgressSnapshot{
		TotalRequests: 120,
		Requests:      80,
		Percent:       66.5,
		LastMessage:   "扫描进度更新",
	})

	if item.TotalRequests != 120 || item.RealRequests != 80 {
		t.Fatalf("unexpected request counts: %+v", item)
	}
	if item.ProgressPercent != 66.5 {
		t.Fatalf("ProgressPercent = %v, want 66.5", item.ProgressPercent)
	}
	if item.LastMessage != "扫描进度更新" {
		t.Fatalf("LastMessage = %q, want 扫描进度更新", item.LastMessage)
	}
}

func TestCalculateTaskDurationSeconds(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, 8, 26, 10, 0, 0, 0, time.FixedZone("CST", 8*3600))
	finishedAt := startedAt.Add(125 * time.Second)

	if got := calculateTaskDurationSeconds(&startedAt, &finishedAt, startedAt); got != 125 {
		t.Fatalf("calculateTaskDurationSeconds() = %d, want 125", got)
	}
}

func TestCalculateSavedRequests(t *testing.T) {
	t.Parallel()

	if got := calculateSavedRequests(120, 80); got != 40 {
		t.Fatalf("calculateSavedRequests() = %d, want 40", got)
	}
	if got := calculateSavedRequests(50, 70); got != 0 {
		t.Fatalf("calculateSavedRequests() negative guard = %d, want 0", got)
	}
}

func TestHasHighRiskResult(t *testing.T) {
	t.Parallel()

	if !hasHighRiskResult(dto.ScanTaskListItem{CriticalCount: 1}) {
		t.Fatalf("expected critical count to be treated as high risk")
	}
	if !hasHighRiskResult(dto.ScanTaskListItem{HighCount: 1}) {
		t.Fatalf("expected high count to be treated as high risk")
	}
	if hasHighRiskResult(dto.ScanTaskListItem{MediumCount: 1, InfoCount: 2}) {
		t.Fatalf("did not expect medium/info only result to be treated as high risk")
	}
}

func TestListHighRiskTasksIncludesRuntimeSummary(t *testing.T) {
	t.Parallel()

	runtimeDir := t.TempDir()
	runningState, err := scanruntime.NewState(3, "task-3", "runtime-task", 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer runningState.Close()

	runningState.RecordResult("runtime-high", "弃用 TLS/SSL 协议检测（证书安全）", "high", nil)
	runningState.UpdateProgress(func(snapshot *scanruntime.TaskProgressSnapshot) {
		snapshot.Requests = 6
		snapshot.TotalRequests = 20
		snapshot.Percent = 30
		snapshot.LastMessage = "运行时已发现高危"
	})

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			listAllItems: []dto.ScanTaskListItem{
				{ID: 3, TaskNo: "task-3", Name: "runtime-task", Status: "running"},
				{ID: 2, TaskNo: "task-2", Name: "db-task", Status: "success", HighCount: 2},
				{ID: 1, TaskNo: "task-1", Name: "safe-task", Status: "success", MediumCount: 1},
			},
		},
		states: map[int64]*scanTaskRuntime{
			3: newScanTaskRuntime(runningState),
		},
	}

	page, err := svc.List(context.Background(), dto.ListScanTasksQuery{
		Page:        1,
		PageSize:    10,
		HasHighRisk: true,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if page.Total != 2 {
		t.Fatalf("Total = %d, want 2", page.Total)
	}
	if len(page.Items) != 2 {
		t.Fatalf("len(Items) = %d, want 2", len(page.Items))
	}
	if page.Items[0].ID != 3 {
		t.Fatalf("first item ID = %d, want 3", page.Items[0].ID)
	}
	if page.Items[0].HighCount != 1 {
		t.Fatalf("runtime high count = %d, want 1", page.Items[0].HighCount)
	}
	if page.Items[0].RealRequests != 6 || page.Items[0].TotalRequests != 20 {
		t.Fatalf("unexpected runtime request stats: %+v", page.Items[0])
	}
	if page.Items[1].ID != 2 {
		t.Fatalf("second item ID = %d, want 2", page.Items[1].ID)
	}
}

func TestListHighRiskTasksPaginatesFilteredItems(t *testing.T) {
	t.Parallel()

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			listAllItems: []dto.ScanTaskListItem{
				{ID: 5, TaskNo: "task-5", Status: "success", CriticalCount: 1},
				{ID: 4, TaskNo: "task-4", Status: "success", HighCount: 1},
				{ID: 3, TaskNo: "task-3", Status: "success", MediumCount: 2},
			},
		},
		states: map[int64]*scanTaskRuntime{},
	}

	page, err := svc.List(context.Background(), dto.ListScanTasksQuery{
		Page:        2,
		PageSize:    1,
		HasHighRisk: true,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if page.Total != 2 || page.TotalPages != 2 {
		t.Fatalf("unexpected pagination: %+v", page)
	}
	if len(page.Items) != 1 || page.Items[0].ID != 4 {
		t.Fatalf("unexpected page items: %+v", page.Items)
	}
}

func TestStatsSavedRequestsOnlyUsesPersistedSuccessfulTasks(t *testing.T) {
	t.Parallel()

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			statsResult: &dto.ScanTaskStats{
				Total:         18,
				Running:       1,
				SavedRequests: 12345,
			},
		},
	}

	stats, err := svc.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}

	if stats.Total != 18 || stats.Running != 1 {
		t.Fatalf("unexpected count stats: %+v", stats)
	}
	if stats.SavedRequests != 12345 {
		t.Fatalf("SavedRequests = %d, want 12345", stats.SavedRequests)
	}
}

func TestGetLogsSupportsRunningForwardAndBeforeDirections(t *testing.T) {
	t.Parallel()

	runtimeDir := t.TempDir()
	runningState, err := scanruntime.NewState(20, "task-20", "running-task", 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer runningState.Close()

	runningState.Append("info", "task_created", "扫描任务已创建，等待执行")
	runningState.Append("error", "scanner_error", "scanner error")
	runningState.Append("info", "task_started", "扫描任务开始执行")
	runningState.Append("warn", "stderr", "warning")
	runningState.Append("info", "process_started", "扫描子进程已启动")

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			tasks: map[int64]*entity.ScanTask{
				20: {
					ID:        20,
					TaskNo:    "task-20",
					Name:      "running-task",
					Status:    "running",
					CreatedBy: "tester",
				},
			},
		},
		states: map[int64]*scanTaskRuntime{
			20: newScanTaskRuntime(runningState),
		},
	}

	forward, err := svc.GetLogs(context.Background(), 20, 1, 2, "")
	if err != nil {
		t.Fatalf("GetLogs() forward error = %v", err)
	}
	if len(forward.Events) != 1 || forward.Events[0].Seq != 3 {
		t.Fatalf("GetLogs() forward events = %+v, want seq 3", forward.Events)
	}
	if forward.NextOffset != 3 {
		t.Fatalf("GetLogs() forward NextOffset = %d, want 3", forward.NextOffset)
	}
	if !forward.HasMore {
		t.Fatalf("GetLogs() forward HasMore = false, want true")
	}

	before, err := svc.GetLogs(context.Background(), 20, 0, 2, "before")
	if err != nil {
		t.Fatalf("GetLogs() before error = %v", err)
	}
	if len(before.Events) != 2 || before.Events[0].Seq != 3 || before.Events[1].Seq != 5 {
		t.Fatalf("GetLogs() before events = %+v, want seq 3 and 5", before.Events)
	}
	if before.NextOffset != 3 {
		t.Fatalf("GetLogs() before NextOffset = %d, want 3", before.NextOffset)
	}
	if !before.HasMore {
		t.Fatalf("GetLogs() before HasMore = false, want true")
	}
}

func TestSubscribeUsesOffsetForSnapshotEvents(t *testing.T) {
	t.Parallel()

	runtimeDir := t.TempDir()
	runningState, err := scanruntime.NewState(21, "task-21", "running-task", 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer runningState.Close()

	runningState.Append("info", "first", "first event")
	runningState.Append("info", "second", "second event")
	runningState.Append("info", "third", "third event")

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			tasks: map[int64]*entity.ScanTask{
				21: {
					ID:        21,
					TaskNo:    "task-21",
					Name:      "running-task",
					Status:    "running",
					CreatedBy: "tester",
				},
			},
		},
		states: map[int64]*scanTaskRuntime{
			21: newScanTaskRuntime(runningState),
		},
	}

	_, _, events, nextOffset, ch, _, _, cancel, err := svc.Subscribe(context.Background(), 21, 2)
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	if cancel != nil {
		defer cancel()
	}
	if ch == nil {
		t.Fatalf("Subscribe() channel = nil, want active stream channel")
	}
	if len(events) != 1 || events[0].Seq != 3 {
		t.Fatalf("Subscribe() events = %+v, want seq 3", events)
	}
	if nextOffset != 3 {
		t.Fatalf("Subscribe() NextOffset = %d, want 3", nextOffset)
	}
}

func TestFinishSuccessTaskRemovesResumeFile(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	runtimeDir := filepath.Join(rootDir, "data", "runtime")
	state, err := scanruntime.NewState(18, "task-18", "success-task", 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			tasks: map[int64]*entity.ScanTask{
				18: {ID: 18, TaskNo: "task-18", Name: "success-task", Status: "running", CreatedBy: "tester"},
			},
		},
		runtimeDir: runtimeDir,
		states: map[int64]*scanTaskRuntime{
			18: newScanTaskRuntime(state),
		},
	}

	resumeFile := svc.resumeFilePath(18)
	if err := os.WriteFile(resumeFile, []byte("resume-data"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	startedAt := time.Date(2026, 8, 26, 11, 0, 0, 0, time.FixedZone("CST", 8*3600))
	svc.finishSuccessTask(18, svc.getRuntime(18), startedAt)

	if _, err := os.Stat(resumeFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resume file still exists or unexpected error: %v", err)
	}
}

func TestFinishPausedTaskKeepsResumeFile(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	runtimeDir := filepath.Join(rootDir, "data", "runtime")
	state, err := scanruntime.NewState(19, "task-19", "paused-task", 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			tasks: map[int64]*entity.ScanTask{
				19: {ID: 19, TaskNo: "task-19", Name: "paused-task", Status: "running", CreatedBy: "tester"},
			},
		},
		runtimeDir: runtimeDir,
		states: map[int64]*scanTaskRuntime{
			19: newScanTaskRuntime(state),
		},
	}

	resumeFile := svc.resumeFilePath(19)
	if err := os.WriteFile(resumeFile, []byte("resume-data"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	startedAt := time.Date(2026, 8, 26, 11, 5, 0, 0, time.FixedZone("CST", 8*3600))
	svc.finishPausedTask(19, svc.getRuntime(19), &startedAt)

	if _, err := os.Stat(resumeFile); err != nil {
		t.Fatalf("resume file should remain after pause, got error: %v", err)
	}
}

func TestCancelRequestsRunningTaskCancellation(t *testing.T) {
	t.Parallel()

	runtimeDir := t.TempDir()
	runningState, err := scanruntime.NewState(12, "task-12", "running-task", 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer runningState.Close()

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			tasks: map[int64]*entity.ScanTask{
				12: {
					ID:        12,
					TaskNo:    "task-12",
					Name:      "running-task",
					Status:    "running",
					CreatedBy: "tester",
				},
			},
		},
		states: map[int64]*scanTaskRuntime{
			12: newScanTaskRuntime(runningState),
		},
	}

	resp, err := svc.Cancel(context.Background(), 12)
	if err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	if !resp.CancelRequested {
		t.Fatalf("CancelRequested = false, want true")
	}
	if resp.Status != "running" {
		t.Fatalf("Status = %q, want running", resp.Status)
	}

	runtime := svc.getRuntime(12)
	if runtime == nil || !runtime.IsCancelRequested() {
		t.Fatalf("expected runtime cancellation flag to be set")
	}

	events := runningState.EventsSince(0, 10).Events
	found := false
	for _, event := range events {
		if event.Type == "task_cancel_requested" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected task_cancel_requested event, got %+v", events)
	}
}

func TestPauseRequestsRunningTaskPause(t *testing.T) {
	t.Parallel()

	runtimeDir := t.TempDir()
	runningState, err := scanruntime.NewState(15, "task-15", "running-task", 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer runningState.Close()

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			tasks: map[int64]*entity.ScanTask{
				15: {
					ID:        15,
					TaskNo:    "task-15",
					Name:      "running-task",
					Status:    "running",
					CreatedBy: "tester",
				},
			},
		},
		states: map[int64]*scanTaskRuntime{
			15: newScanTaskRuntime(runningState),
		},
	}

	resp, err := svc.Pause(context.Background(), 15)
	if err != nil {
		t.Fatalf("Pause() error = %v", err)
	}
	if !resp.PauseRequested {
		t.Fatalf("PauseRequested = false, want true")
	}
	if resp.Status != "running" {
		t.Fatalf("Status = %q, want running", resp.Status)
	}

	runtime := svc.getRuntime(15)
	if runtime == nil || !runtime.IsPauseRequested() {
		t.Fatalf("expected runtime pause flag to be set")
	}

	events := runningState.EventsSince(0, 10).Events
	found := false
	for _, event := range events {
		if event.Type == "task_pause_requested" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected task_pause_requested event, got %+v", events)
	}
}

func TestCancelMarksStrandedRunningTaskCancelled(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, 8, 26, 10, 0, 0, 0, time.FixedZone("CST", 8*3600))
	repo := &scanTaskRepositoryStub{
		tasks: map[int64]*entity.ScanTask{
			13: {
				ID:        13,
				TaskNo:    "task-13",
				Name:      "stranded-task",
				Status:    "running",
				CreatedBy: "tester",
				StartedAt: &startedAt,
			},
		},
	}
	svc := &scanTaskService{
		repository: repo,
		logger:     logx.New(),
		states:     map[int64]*scanTaskRuntime{},
	}

	resp, err := svc.Cancel(context.Background(), 13)
	if err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	if resp.Status != "cancelled" {
		t.Fatalf("Status = %q, want cancelled", resp.Status)
	}
	if len(repo.updateStatusCalls) != 1 {
		t.Fatalf("updateStatusCalls = %d, want 1", len(repo.updateStatusCalls))
	}
	if repo.updateStatusCalls[0].status != "cancelled" {
		t.Fatalf("updated status = %q, want cancelled", repo.updateStatusCalls[0].status)
	}
}

func TestCancelRejectsFinishedTask(t *testing.T) {
	t.Parallel()

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			tasks: map[int64]*entity.ScanTask{
				14: {
					ID:        14,
					TaskNo:    "task-14",
					Name:      "finished-task",
					Status:    "success",
					CreatedBy: "tester",
				},
			},
		},
		states: map[int64]*scanTaskRuntime{},
	}

	_, err := svc.Cancel(context.Background(), 14)
	if err != ErrScanTaskNotCancelable {
		t.Fatalf("Cancel() error = %v, want %v", err, ErrScanTaskNotCancelable)
	}
}

func TestCancelPausedTaskMarksCancelledImmediately(t *testing.T) {
	t.Parallel()

	runtimeDir := t.TempDir()
	pausedState, err := scanruntime.NewState(17, "task-17", "paused-task", 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer pausedState.Close()

	pausedAt := time.Date(2026, 8, 26, 10, 30, 0, 0, time.FixedZone("CST", 8*3600))
	pausedState.MarkFinished("paused", pausedAt, "扫描任务已暂停")

	repo := &scanTaskRepositoryStub{
		tasks: map[int64]*entity.ScanTask{
			17: {
				ID:         17,
				TaskNo:     "task-17",
				Name:       "paused-task",
				Status:     "paused",
				CreatedBy:  "tester",
				FinishedAt: &pausedAt,
			},
		},
	}
	svc := &scanTaskService{
		repository: repo,
		states: map[int64]*scanTaskRuntime{
			17: newScanTaskRuntime(pausedState),
		},
	}

	resp, err := svc.Cancel(context.Background(), 17)
	if err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	if !resp.CancelRequested {
		t.Fatalf("CancelRequested = false, want true")
	}
	if resp.Status != "cancelled" {
		t.Fatalf("Status = %q, want cancelled", resp.Status)
	}
	if len(repo.updateStatusCalls) != 1 {
		t.Fatalf("updateStatusCalls = %d, want 1", len(repo.updateStatusCalls))
	}
	if repo.updateStatusCalls[0].status != "cancelled" {
		t.Fatalf("updated status = %q, want cancelled", repo.updateStatusCalls[0].status)
	}

	progress := pausedState.SnapshotProgress()
	if !progress.Finished || progress.FinishedStatus != "cancelled" {
		t.Fatalf("progress = %+v, want finished cancelled", progress)
	}
}

func TestRescanCreatesNewTaskFromExistingConfiguration(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	sourceTask := &entity.ScanTask{
		ID:                            31,
		TaskNo:                        "task-31",
		Name:                          "daily-web-scan",
		Description:                   ptr("source description"),
		Status:                        "success",
		CreatedBy:                     "tester",
		StartedAt:                     ptrTime(time.Date(2026, 8, 26, 10, 0, 0, 0, time.FixedZone("CST", 8*3600))),
		FinishedAt:                    ptrTime(time.Date(2026, 8, 26, 10, 5, 0, 0, time.FixedZone("CST", 8*3600))),
		Targets:                       `["https://example.com","https://admin.example.com"]`,
		InlineTargetsList:             ptr("https://example.com\nhttps://admin.example.com\n"),
		ExcludeTargets:                `["https://example.com/logout"]`,
		ScanAllIPs:                    true,
		IPVersion:                     `["4","6"]`,
		InputFileMode:                 "list",
		NewTemplates:                  true,
		AutomaticScan:                 true,
		EnableGlobalMatchersTemplates: true,
		Tags:                          `["cve","exposure"]`,
		IncludeIDs:                    `["CVE-2026-0001"]`,
		Severities:                    `["high","critical"]`,
		Protocols:                     `["http","tcp"]`,
		StoreResponse:                 true,
		CustomHeaders:                 `["X-Test: 1"]`,
		FollowRedirects:               true,
		MaxRedirects:                  3,
		RateLimit:                     20,
		RateLimitDuration:             2000,
		BulkSize:                      7,
		TemplateThreads:               8,
		Timeout:                       12,
		Retries:                       2,
		MaxHostError:                  5,
		Project:                       true,
		ProjectPath:                   ptr("/tmp/manscan-project"),
		ScanStrategy:                  ptr("auto"),
		Headless:                      true,
		PageTimeout:                   30,
		HeadlessOptionalArguments:     `["--no-sandbox"]`,
		Proxy:                         `["http://127.0.0.1:8080"]`,
		EnableProgressBar:             true,
		StatsInterval:                 2,
		MetricsPort:                   9099,
	}
	repo := &scanTaskRepositoryStub{
		tasks:        map[int64]*entity.ScanTask{31: sourceTask},
		nextCreateID: 88,
	}

	called := false
	var capturedTaskID int64
	var capturedPlan *normalizedTaskRequest
	svc := &scanTaskService{
		repository: repo,
		rootDir:    rootDir,
		runtimeDir: filepath.Join(rootDir, "data", "runtime"),
		states:     map[int64]*scanTaskRuntime{},
		taskRunner: func(taskID int64, plan *normalizedTaskRequest, runtime *scanTaskRuntime) {
			called = true
			capturedTaskID = taskID
			capturedPlan = plan
			if runtime == nil || runtime.state == nil {
				t.Fatalf("runtime is nil")
			}
		},
	}

	summary, err := svc.Rescan(context.Background(), 31)
	if err != nil {
		t.Fatalf("Rescan() error = %v", err)
	}
	if !called {
		t.Fatalf("expected taskRunner to be called")
	}
	if summary.ID != 88 || capturedTaskID != 88 {
		t.Fatalf("new task ID summary=%d runner=%d, want 88", summary.ID, capturedTaskID)
	}
	if summary.TaskNo == "" || summary.TaskNo == sourceTask.TaskNo {
		t.Fatalf("TaskNo = %q, want non-empty new task no", summary.TaskNo)
	}
	if summary.Status != "pending" || summary.StartedAt != nil || summary.FinishedAt != nil {
		t.Fatalf("unexpected new task summary: %+v", summary)
	}

	if len(repo.createdTasks) != 1 {
		t.Fatalf("createdTasks = %d, want 1", len(repo.createdTasks))
	}
	created := repo.createdTasks[0]
	if created.ID != 88 || created.Name != sourceTask.Name || created.CreatedBy != sourceTask.CreatedBy {
		t.Fatalf("unexpected created task identity: %+v", created)
	}
	if created.StartedAt != nil || created.FinishedAt != nil || created.Status != "pending" {
		t.Fatalf("created task carried runtime state: %+v", created)
	}
	if created.Targets != `["https://example.com","https://admin.example.com"]` {
		t.Fatalf("Targets = %s", created.Targets)
	}
	if created.ExcludeTargets != sourceTask.ExcludeTargets || created.Tags != sourceTask.Tags || created.Severities != sourceTask.Severities {
		t.Fatalf("created task did not copy filters: %+v", created)
	}
	if !created.ScanAllIPs || !created.NewTemplates || !created.AutomaticScan || !created.Headless {
		t.Fatalf("created task did not copy boolean options: %+v", created)
	}
	if created.RateLimit != 20 || created.TemplateThreads != 8 || created.Timeout != 12 || created.MetricsPort != 9099 {
		t.Fatalf("created task did not copy numeric options: %+v", created)
	}
	if capturedPlan == nil || len(capturedPlan.CollectedTargets) != 2 {
		t.Fatalf("unexpected captured plan: %+v", capturedPlan)
	}
	if svc.getRuntime(88) == nil {
		t.Fatalf("expected new runtime to be registered")
	}
}

func TestRescanRejectsSourceTaskWithoutTargets(t *testing.T) {
	t.Parallel()

	repo := &scanTaskRepositoryStub{
		tasks: map[int64]*entity.ScanTask{
			32: {
				ID:        32,
				TaskNo:    "task-32",
				Name:      "empty-task",
				Status:    "success",
				CreatedBy: "tester",
			},
		},
	}
	svc := &scanTaskService{
		repository: repo,
		runtimeDir: t.TempDir(),
		states:     map[int64]*scanTaskRuntime{},
		taskRunner: func(taskID int64, plan *normalizedTaskRequest, runtime *scanTaskRuntime) {
			t.Fatalf("taskRunner should not be called for invalid source task")
		},
	}

	_, err := svc.Rescan(context.Background(), 32)
	if !errors.Is(err, ErrScanTaskInvalidConfiguration) {
		t.Fatalf("Rescan() error = %v, want ErrScanTaskInvalidConfiguration", err)
	}
	if len(repo.createdTasks) != 0 {
		t.Fatalf("createdTasks = %d, want 0", len(repo.createdTasks))
	}
}

func TestResumePausedTaskStartsRunningRun(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	runtimeDir := filepath.Join(rootDir, "data", "runtime", "16")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	task := &entity.ScanTask{
		ID:        16,
		TaskNo:    "task-16",
		Name:      "paused-task",
		Status:    "paused",
		CreatedBy: "tester",
		Targets:   `["https://example.com"]`,
	}
	startedAt := time.Date(2026, 8, 26, 9, 30, 0, 0, time.FixedZone("CST", 8*3600))
	task.StartedAt = &startedAt
	repo := &scanTaskRepositoryStub{
		tasks: map[int64]*entity.ScanTask{16: task},
	}

	called := false
	var capturedPlan *normalizedTaskRequest
	var capturedRuntime *scanTaskRuntime
	svc := &scanTaskService{
		repository: repo,
		rootDir:    rootDir,
		runtimeDir: filepath.Join(rootDir, "data", "runtime"),
		states:     map[int64]*scanTaskRuntime{},
		taskRunner: func(taskID int64, plan *normalizedTaskRequest, runtime *scanTaskRuntime) {
			called = true
			if taskID != 16 {
				t.Fatalf("taskID = %d, want 16", taskID)
			}
			capturedPlan = plan
			capturedRuntime = runtime
		},
	}

	resp, err := svc.Resume(context.Background(), 16)
	if err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	if !resp.ResumeRequested {
		t.Fatalf("ResumeRequested = false, want true")
	}
	if resp.Status != "running" {
		t.Fatalf("Status = %q, want running", resp.Status)
	}
	if !called {
		t.Fatalf("expected taskRunner to be called")
	}
	if capturedPlan == nil || len(capturedPlan.CollectedTargets) != 1 || capturedPlan.CollectedTargets[0] != "https://example.com" {
		t.Fatalf("unexpected resumed plan: %+v", capturedPlan)
	}
	if capturedRuntime == nil || svc.getRuntime(16) != capturedRuntime {
		t.Fatalf("expected resumed runtime to be registered")
	}
	progress := capturedRuntime.state.SnapshotProgress()
	if progress.Finished || progress.FinishedStatus != "running" {
		t.Fatalf("progress after resume = %+v, want unfinished running", progress)
	}
	if len(repo.prepareForResumeCalls) != 1 || repo.prepareForResumeCalls[0] != 16 {
		t.Fatalf("prepareForResumeCalls = %+v, want [16]", repo.prepareForResumeCalls)
	}
	if repo.tasks[16].StartedAt == nil || !repo.tasks[16].StartedAt.Equal(startedAt) {
		t.Fatalf("StartedAt after resume = %v, want %v", repo.tasks[16].StartedAt, startedAt)
	}
	if repo.tasks[16].FinishedAt != nil {
		t.Fatalf("FinishedAt after resume = %v, want nil", repo.tasks[16].FinishedAt)
	}
}

func TestResumePausedTaskRejectsDuplicateResume(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	task := &entity.ScanTask{
		ID:        17,
		TaskNo:    "task-17",
		Name:      "paused-task",
		Status:    "paused",
		CreatedBy: "tester",
		Targets:   `["https://example.com"]`,
	}
	repo := &scanTaskRepositoryStub{
		tasks: map[int64]*entity.ScanTask{17: task},
	}
	svc := &scanTaskService{
		repository: repo,
		rootDir:    rootDir,
		runtimeDir: filepath.Join(rootDir, "data", "runtime"),
		states:     map[int64]*scanTaskRuntime{},
		taskRunner: func(taskID int64, plan *normalizedTaskRequest, runtime *scanTaskRuntime) {},
	}

	if _, err := svc.Resume(context.Background(), 17); err != nil {
		t.Fatalf("first Resume() error = %v", err)
	}
	if _, err := svc.Resume(context.Background(), 17); !errors.Is(err, ErrScanTaskNotResumable) {
		t.Fatalf("second Resume() error = %v, want ErrScanTaskNotResumable", err)
	}
	if len(repo.prepareForResumeCalls) != 1 {
		t.Fatalf("prepareForResumeCalls = %d, want 1", len(repo.prepareForResumeCalls))
	}
}

func TestRunTaskPreservesExistingStartedAt(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "manscan"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	runtimeDir := filepath.Join(rootDir, "data", "runtime")
	startedAt := time.Date(2026, 8, 26, 9, 30, 0, 0, time.FixedZone("CST", 8*3600))
	task := &entity.ScanTask{
		ID:        29,
		TaskNo:    "task-29",
		Name:      "resumed-task",
		Status:    "pending",
		CreatedBy: "tester",
		StartedAt: &startedAt,
		Targets:   `["https://example.com"]`,
	}
	repo := &scanTaskRepositoryStub{
		tasks: map[int64]*entity.ScanTask{29: task},
	}

	state, err := scanruntime.NewState(task.ID, task.TaskNo, task.Name, 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	svc := &scanTaskService{
		repository: repo,
		rootDir:    rootDir,
		runtimeDir: runtimeDir,
		states: map[int64]*scanTaskRuntime{
			task.ID: newScanTaskRuntime(state),
		},
	}
	runtime := svc.getRuntime(task.ID)

	svc.runTask(task.ID, &normalizedTaskRequest{
		Raw:              dto.CreateScanTaskRequest{},
		Name:             task.Name,
		CreatedBy:        task.CreatedBy,
		CollectedTargets: []string{"https://example.com"},
	}, runtime)

	if len(repo.updateStatusCalls) < 2 {
		t.Fatalf("updateStatusCalls = %d, want at least 2", len(repo.updateStatusCalls))
	}
	runningCall := repo.updateStatusCalls[0]
	if runningCall.status != "running" {
		t.Fatalf("first status = %q, want running", runningCall.status)
	}
	if runningCall.startedAt != nil {
		t.Fatalf("running startedAt update = %v, want nil to preserve original", runningCall.startedAt)
	}
	if repo.tasks[29].StartedAt == nil || !repo.tasks[29].StartedAt.Equal(startedAt) {
		t.Fatalf("task StartedAt = %v, want %v", repo.tasks[29].StartedAt, startedAt)
	}
}

func TestScanTaskRuntimeRequestCancelTriggersTerminate(t *testing.T) {
	t.Parallel()

	runtime := newScanTaskRuntime(nil)

	cancelCalled := false
	terminateCalled := false
	if !runtime.AttachCancel(func() {
		cancelCalled = true
	}) {
		t.Fatalf("AttachCancel() = false, want true")
	}
	if !runtime.AttachTerminator(func() {
		terminateCalled = true
	}) {
		t.Fatalf("AttachTerminator() = false, want true")
	}

	alreadyRequested := runtime.RequestCancel()
	if alreadyRequested {
		t.Fatalf("RequestCancel() = true, want false on first request")
	}
	if !cancelCalled {
		t.Fatalf("expected cancel func to be called")
	}
	if !terminateCalled {
		t.Fatalf("expected terminate func to be called")
	}
}

func TestScanTaskRuntimeRequestPauseTriggersInterrupt(t *testing.T) {
	t.Parallel()

	runtime := newScanTaskRuntime(nil)

	interruptCalled := false
	if !runtime.AttachInterrupt(func() {
		interruptCalled = true
	}) {
		t.Fatalf("AttachInterrupt() = false, want true")
	}

	alreadyRequested, accepted := runtime.RequestPause()
	if alreadyRequested || !accepted {
		t.Fatalf("RequestPause() = (%v, %v), want (false, true)", alreadyRequested, accepted)
	}
	if !interruptCalled {
		t.Fatalf("expected interrupt func to be called")
	}
}

func TestScanTaskRuntimeAttachTerminatorAfterCancelRunsImmediately(t *testing.T) {
	t.Parallel()

	runtime := newScanTaskRuntime(nil)
	if alreadyRequested := runtime.RequestCancel(); alreadyRequested {
		t.Fatalf("RequestCancel() = true, want false on first request")
	}

	terminateCalled := false
	if !runtime.AttachTerminator(func() {
		terminateCalled = true
	}) {
		t.Fatalf("AttachTerminator() = false, want true")
	}
	if !terminateCalled {
		t.Fatalf("expected terminate func to run immediately after prior cancel request")
	}
}

type statusUpdateCall struct {
	taskID     int64
	status     string
	startedAt  *time.Time
	finishedAt *time.Time
}

type scanTaskRepositoryStub struct {
	listResult            *dto.PageResult[dto.ScanTaskListItem]
	listAllItems          []dto.ScanTaskListItem
	statsResult           *dto.ScanTaskStats
	tasks                 map[int64]*entity.ScanTask
	createdTasks          []*entity.ScanTask
	nextCreateID          int64
	createErr             error
	findByIDErr           error
	prepareForResumeCalls []int64
	prepareForResumeErr   error
	updateStatusErr       error
	updateStatusCalls     []statusUpdateCall
}

func (s *scanTaskRepositoryStub) Create(_ context.Context, task *entity.ScanTask) error {
	if s.createErr != nil {
		return s.createErr
	}
	if task == nil {
		return errors.New("scan task is nil")
	}
	if task.ID == 0 {
		if s.nextCreateID > 0 {
			task.ID = s.nextCreateID
			s.nextCreateID++
		} else {
			task.ID = int64(len(s.createdTasks) + 1)
		}
	}

	copyTask := *task
	s.createdTasks = append(s.createdTasks, &copyTask)
	if s.tasks == nil {
		s.tasks = make(map[int64]*entity.ScanTask)
	}
	storedTask := copyTask
	s.tasks[task.ID] = &storedTask
	return nil
}

func (s *scanTaskRepositoryStub) FindByID(_ context.Context, taskID int64) (*entity.ScanTask, error) {
	if s.findByIDErr != nil {
		return nil, s.findByIDErr
	}
	if s.tasks == nil {
		return nil, gorm.ErrRecordNotFound
	}

	task, ok := s.tasks[taskID]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}

	copyTask := *task
	return &copyTask, nil
}

func (s *scanTaskRepositoryStub) List(_ context.Context, _ dto.ListScanTasksQuery) (*dto.PageResult[dto.ScanTaskListItem], error) {
	if s.listResult != nil {
		return s.listResult, nil
	}
	return &dto.PageResult[dto.ScanTaskListItem]{}, nil
}

func (s *scanTaskRepositoryStub) ListNameOptions(_ context.Context, _ dto.ListScanTaskNameOptionsQuery) (*dto.PageResult[dto.ScanTaskNameOption], error) {
	return &dto.PageResult[dto.ScanTaskNameOption]{}, nil
}

func (s *scanTaskRepositoryStub) ListAll(_ context.Context, _ dto.ListScanTasksQuery) ([]dto.ScanTaskListItem, error) {
	items := make([]dto.ScanTaskListItem, len(s.listAllItems))
	copy(items, s.listAllItems)
	return items, nil
}

func (s *scanTaskRepositoryStub) Stats(_ context.Context) (*dto.ScanTaskStats, error) {
	if s.statsResult != nil {
		copyStats := *s.statsResult
		return &copyStats, nil
	}
	return &dto.ScanTaskStats{}, nil
}

func (s *scanTaskRepositoryStub) FindResultByTaskID(_ context.Context, _ int64) (*entity.ScanTaskResult, error) {
	return nil, nil
}

func (s *scanTaskRepositoryStub) PrepareForResume(_ context.Context, taskID int64) error {
	if s.prepareForResumeErr != nil {
		return s.prepareForResumeErr
	}
	s.prepareForResumeCalls = append(s.prepareForResumeCalls, taskID)
	if task, ok := s.tasks[taskID]; ok {
		if task.Status != "paused" {
			return gorm.ErrRecordNotFound
		}
		task.Status = "running"
		task.FinishedAt = nil
		return nil
	}
	return gorm.ErrRecordNotFound
}

func (s *scanTaskRepositoryStub) UpdateStatus(_ context.Context, taskID int64, status string, startedAt, finishedAt *time.Time) error {
	if s.updateStatusErr != nil {
		return s.updateStatusErr
	}

	s.updateStatusCalls = append(s.updateStatusCalls, statusUpdateCall{
		taskID:     taskID,
		status:     status,
		startedAt:  startedAt,
		finishedAt: finishedAt,
	})

	if task, ok := s.tasks[taskID]; ok {
		task.Status = status
		if startedAt != nil {
			copied := *startedAt
			task.StartedAt = &copied
		}
		if finishedAt != nil {
			copied := *finishedAt
			task.FinishedAt = &copied
		}
	}
	return nil
}

func (s *scanTaskRepositoryStub) UpsertResult(_ context.Context, _ *entity.ScanTaskResult) error {
	return nil
}

type vulnerabilityRepositoryStub struct {
	items      []*entity.Vulnerability
	batchCalls int
}

func (s *vulnerabilityRepositoryStub) Upsert(_ context.Context, vulnerability *entity.Vulnerability) error {
	return s.UpsertBatch(context.Background(), []*entity.Vulnerability{vulnerability})
}

func (s *vulnerabilityRepositoryStub) UpsertBatch(_ context.Context, vulnerabilities []*entity.Vulnerability) error {
	s.batchCalls++
	for _, vulnerability := range vulnerabilities {
		if vulnerability == nil {
			continue
		}
		copied := *vulnerability
		s.items = append(s.items, &copied)
	}
	return nil
}

func (s *vulnerabilityRepositoryStub) List(_ context.Context, _ dto.ListVulnerabilitiesQuery) (*dto.PageResult[entity.Vulnerability], error) {
	return &dto.PageResult[entity.Vulnerability]{}, nil
}

func (s *vulnerabilityRepositoryStub) FindByID(_ context.Context, _ int64) (*entity.Vulnerability, error) {
	return nil, gorm.ErrRecordNotFound
}

func (s *vulnerabilityRepositoryStub) UpdateStatus(_ context.Context, _ int64, _ string, _ *time.Time) error {
	return nil
}

func (s *vulnerabilityRepositoryStub) BatchUpdateStatus(_ context.Context, _ []int64, _ string, _ *time.Time) (int64, error) {
	return 0, nil
}

func (s *vulnerabilityRepositoryStub) Delete(_ context.Context, _ []int64) (int64, error) {
	return 0, nil
}

type templateRepositoryStub struct {
	details map[string]*dto.TemplateDetail
}

func (s *templateRepositoryStub) List() ([]dto.TemplateListItem, error) {
	return nil, nil
}

func (s *templateRepositoryStub) FindByID(templateID string) (*dto.TemplateDetail, error) {
	if s.details == nil {
		return nil, nil
	}
	detail := s.details[templateID]
	if detail == nil {
		return nil, nil
	}
	copied := *detail
	copied.Protocols = append([]string(nil), detail.Protocols...)
	copied.Tags = append([]string(nil), detail.Tags...)
	copied.Reference = append([]string(nil), detail.Reference...)
	return &copied, nil
}

func (s *templateRepositoryStub) Tags() ([]string, error) {
	return nil, nil
}

func (s *templateRepositoryStub) Protocols() ([]string, error) {
	return nil, nil
}

func (s *templateRepositoryStub) Stats() (*dto.TemplateStats, error) {
	return &dto.TemplateStats{}, nil
}

func ptr(value string) *string {
	return &value
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
