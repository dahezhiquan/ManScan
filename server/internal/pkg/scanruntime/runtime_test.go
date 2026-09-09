package scanruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShouldHideFrontendLogEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event TaskLogEvent
		want  bool
	}{
		{
			name: "hide warn level events",
			event: TaskLogEvent{
				Level:   "warn",
				Type:    "stdout",
				Message: "warning message",
			},
			want: true,
		},
		{
			name: "hide scanner errors",
			event: TaskLogEvent{
				Level:   "error",
				Type:    "scanner_error",
				Message: "[CVE-2025-25256][tcp] 10.107.71.65:8889: tls: first record does not look like a TLS handshake",
			},
			want: true,
		},
		{
			name: "hide task errors",
			event: TaskLogEvent{
				Level:   "error",
				Type:    "task_failed",
				Message: "扫描任务执行失败",
			},
			want: true,
		},
		{
			name: "keep info events",
			event: TaskLogEvent{
				Level:   "info",
				Type:    "task_finished",
				Message: "扫描任务执行完成",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ShouldHideFrontendLogEvent(tt.event)
			if got != tt.want {
				t.Fatalf("ShouldHideFrontendLogEvent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterFrontendLogEvents(t *testing.T) {
	t.Parallel()

	events := []TaskLogEvent{
		{Seq: 1, Level: "info", Type: "task_started", Message: "扫描任务开始执行"},
		{Seq: 2, Level: "warn", Type: "stderr", Message: "warning"},
		{Seq: 3, Level: "error", Type: "scanner_error", Message: "[CVE-2025-25256][tcp] 10.107.71.65:8889: tls: first record does not look like a TLS handshake"},
		{Seq: 4, Level: "error", Type: "task_failed", Message: "扫描任务执行失败"},
	}

	filtered := FilterFrontendLogEvents(events)
	if len(filtered) != 1 {
		t.Fatalf("FilterFrontendLogEvents() len = %d, want 1", len(filtered))
	}

	if filtered[0].Seq != 1 {
		t.Fatalf("FilterFrontendLogEvents() kept unexpected events: %+v", filtered)
	}
}

func TestFilterFrontendLogEventsKeepsLatestHTTPStatsBlock(t *testing.T) {
	t.Parallel()

	events := []TaskLogEvent{
		{Seq: 1, Level: "info", Type: "task_started", Message: "扫描任务开始执行"},
		{Seq: 2, Level: "info", Type: "http_stats", Message: "Top Status Codes:\n  200: 1"},
		{Seq: 3, Level: "info", Type: "http_stats", Message: "Top Status Codes:\n  200: 2"},
	}

	filtered := FilterFrontendLogEvents(events)
	if len(filtered) != 2 {
		t.Fatalf("FilterFrontendLogEvents() len = %d, want 2", len(filtered))
	}
	if filtered[0].Seq != 1 {
		t.Fatalf("FilterFrontendLogEvents() first event = %+v, want seq 1", filtered[0])
	}
	if filtered[1].Seq != 3 {
		t.Fatalf("FilterFrontendLogEvents() second event = %+v, want latest http_stats", filtered[1])
	}
}

func TestBuildFrontendEventsBefore(t *testing.T) {
	t.Parallel()

	events := []TaskLogEvent{
		{Seq: 1, Level: "info", Type: "task_created", Message: "扫描任务已创建，等待执行"},
		{Seq: 2, Level: "error", Type: "scanner_error", Message: "[CVE-2025-25256][tcp] 10.107.71.65:8889: tls: first record does not look like a TLS handshake"},
		{Seq: 3, Level: "info", Type: "task_started", Message: "扫描任务开始执行"},
		{Seq: 4, Level: "warn", Type: "stderr", Message: "warning"},
		{Seq: 5, Level: "info", Type: "task_finished", Message: "扫描任务执行完成"},
	}

	page := buildFrontendEventsBefore(events, 0, 2)
	if len(page.Events) != 2 {
		t.Fatalf("buildFrontendEventsBefore() len = %d, want 2", len(page.Events))
	}

	if page.Events[0].Seq != 3 || page.Events[1].Seq != 5 {
		t.Fatalf("buildFrontendEventsBefore() kept unexpected events: %+v", page.Events)
	}

	if !page.HasMore {
		t.Fatalf("buildFrontendEventsBefore() HasMore = false, want true")
	}

	if page.NextOffset != 3 {
		t.Fatalf("buildFrontendEventsBefore() NextOffset = %d, want 3", page.NextOffset)
	}
}

func TestBuildFrontendEventsBeforeKeepsLatestDuplicateResult(t *testing.T) {
	t.Parallel()

	events := []TaskLogEvent{
		{Seq: 1, Level: "match", Type: "result", Message: "[demo][info] 命中 http://example.com"},
		{Seq: 2, Level: "info", Type: "progress", Message: "扫描进度更新"},
		{Seq: 3, Level: "match", Type: "result", Message: "[other][info] 命中 http://example.com"},
		{Seq: 4, Level: "match", Type: "result", Message: "[demo][info] 命中 http://example.com"},
	}

	page := buildFrontendEventsBefore(events, 0, 10)
	if len(page.Events) != 3 {
		t.Fatalf("buildFrontendEventsBefore() len = %d, want 3: %+v", len(page.Events), page.Events)
	}
	if page.Events[0].Seq != 2 || page.Events[1].Seq != 3 || page.Events[2].Seq != 4 {
		t.Fatalf("buildFrontendEventsBefore() events = %+v, want seq 2,3,4", page.Events)
	}
	if page.HasMore {
		t.Fatalf("buildFrontendEventsBefore() HasMore = true, want false")
	}
}

func TestEventsSinceNextOffsetMatchesLastReturnedSeq(t *testing.T) {
	t.Parallel()

	state, err := NewState(101, "task-101", "runtime-task", 1, t.TempDir())
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	state.Append("info", "first", "first event")
	state.Append("info", "second", "second event")
	state.Append("info", "third", "third event")

	page := state.EventsSince(0, 2)
	if len(page.Events) != 2 {
		t.Fatalf("EventsSince() len = %d, want 2", len(page.Events))
	}
	if page.NextOffset != 2 {
		t.Fatalf("EventsSince() NextOffset = %d, want 2", page.NextOffset)
	}
	if !page.HasMore {
		t.Fatalf("EventsSince() HasMore = false, want true")
	}

	nextPage := state.EventsSince(page.NextOffset, 2)
	if len(nextPage.Events) != 1 || nextPage.Events[0].Seq != 3 {
		t.Fatalf("EventsSince() next page = %+v, want seq 3", nextPage.Events)
	}
	if nextPage.NextOffset != 3 {
		t.Fatalf("EventsSince() next page NextOffset = %d, want 3", nextPage.NextOffset)
	}
	if nextPage.HasMore {
		t.Fatalf("EventsSince() next page HasMore = true, want false")
	}
}

func TestReadFrontendLogEventsBeforeFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	now := time.Now()
	events := []TaskLogEvent{
		{Seq: 1, Time: now, Level: "info", Type: "task_created", Message: "扫描任务已创建，等待执行"},
		{Seq: 2, Time: now, Level: "error", Type: "scanner_error", Message: "[CVE-2025-25256][tcp] 10.107.71.65:8889: tls: first record does not look like a TLS handshake"},
		{Seq: 3, Time: now, Level: "info", Type: "task_started", Message: "扫描任务开始执行"},
		{Seq: 4, Time: now, Level: "warn", Type: "stderr", Message: "warning"},
		{Seq: 5, Time: now, Level: "info", Type: "process_started", Message: "扫描子进程已启动"},
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}

	for _, event := range events {
		encoded, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			_ = file.Close()
			t.Fatalf("Marshal() error = %v", marshalErr)
		}
		if _, writeErr := file.Write(append(encoded, '\n')); writeErr != nil {
			_ = file.Close()
			t.Fatalf("Write() error = %v", writeErr)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	filtered, hasMore, nextOffset, err := ReadFrontendLogEventsBeforeFromFile(path, 0, 2)
	if err != nil {
		t.Fatalf("ReadFrontendLogEventsBeforeFromFile() error = %v", err)
	}

	if len(filtered) != 2 {
		t.Fatalf("ReadFrontendLogEventsBeforeFromFile() len = %d, want 2", len(filtered))
	}

	if filtered[0].Seq != 3 || filtered[1].Seq != 5 {
		t.Fatalf("ReadFrontendLogEventsBeforeFromFile() kept unexpected events: %+v", filtered)
	}

	if !hasMore {
		t.Fatalf("ReadFrontendLogEventsBeforeFromFile() HasMore = false, want true")
	}

	if nextOffset != 3 {
		t.Fatalf("ReadFrontendLogEventsBeforeFromFile() NextOffset = %d, want 3", nextOffset)
	}
}

func TestReadFrontendLogEventsBeforeFromFileKeepsLatestDuplicateResult(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	now := time.Now()
	events := []TaskLogEvent{
		{Seq: 1, Time: now, Level: "match", Type: "result", Message: "[demo][info] 命中 http://example.com"},
		{Seq: 2, Time: now, Level: "info", Type: "progress", Message: "扫描进度更新"},
		{Seq: 3, Time: now, Level: "match", Type: "result", Message: "[other][info] 命中 http://example.com"},
		{Seq: 4, Time: now, Level: "match", Type: "result", Message: "[demo][info] 命中 http://example.com"},
	}
	writeTaskLogEvents(t, path, events)

	filtered, hasMore, nextOffset, err := ReadFrontendLogEventsBeforeFromFile(path, 0, 10)
	if err != nil {
		t.Fatalf("ReadFrontendLogEventsBeforeFromFile() error = %v", err)
	}
	if len(filtered) != 3 {
		t.Fatalf("ReadFrontendLogEventsBeforeFromFile() len = %d, want 3: %+v", len(filtered), filtered)
	}
	if filtered[0].Seq != 2 || filtered[1].Seq != 3 || filtered[2].Seq != 4 {
		t.Fatalf("ReadFrontendLogEventsBeforeFromFile() events = %+v, want seq 2,3,4", filtered)
	}
	if hasMore {
		t.Fatalf("ReadFrontendLogEventsBeforeFromFile() HasMore = true, want false")
	}
	if nextOffset != 2 {
		t.Fatalf("ReadFrontendLogEventsBeforeFromFile() NextOffset = %d, want 2", nextOffset)
	}
}

func TestReadLogEventsFromFileNextOffsetMatchesLastReturnedSeq(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	now := time.Now()
	events := []TaskLogEvent{
		{Seq: 1, Time: now, Level: "info", Type: "first", Message: "first event"},
		{Seq: 2, Time: now, Level: "info", Type: "second", Message: "second event"},
		{Seq: 3, Time: now, Level: "info", Type: "third", Message: "third event"},
	}
	writeTaskLogEvents(t, path, events)

	filtered, hasMore, nextOffset, err := ReadLogEventsFromFile(path, 0, 2)
	if err != nil {
		t.Fatalf("ReadLogEventsFromFile() error = %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("ReadLogEventsFromFile() len = %d, want 2", len(filtered))
	}
	if nextOffset != 2 {
		t.Fatalf("ReadLogEventsFromFile() NextOffset = %d, want 2", nextOffset)
	}
	if !hasMore {
		t.Fatalf("ReadLogEventsFromFile() HasMore = false, want true")
	}

	nextEvents, nextHasMore, nextNextOffset, err := ReadLogEventsFromFile(path, nextOffset, 2)
	if err != nil {
		t.Fatalf("ReadLogEventsFromFile() next page error = %v", err)
	}
	if len(nextEvents) != 1 || nextEvents[0].Seq != 3 {
		t.Fatalf("ReadLogEventsFromFile() next page = %+v, want seq 3", nextEvents)
	}
	if nextNextOffset != 3 {
		t.Fatalf("ReadLogEventsFromFile() next page NextOffset = %d, want 3", nextNextOffset)
	}
	if nextHasMore {
		t.Fatalf("ReadLogEventsFromFile() next page HasMore = true, want false")
	}
}

func TestStreamCommandOutputWithResultHandlerCapturesHTTPStatsBlock(t *testing.T) {
	t.Parallel()

	state, err := NewState(102, "task-102", "runtime-task", 1, t.TempDir())
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	input := strings.NewReader("{\"template-id\":\"demo\"}\n[INF] Top Status Codes:\n[INF]   404: 1\n[INF]   200: 2\n[INF] Top Errors:\n")
	StreamCommandOutputWithResultHandler(input, state, "stdout", true, nil)

	events := state.EventsSince(0, 10).Events
	if len(events) != 2 {
		t.Fatalf("events = %+v, want 2 events including http stats", events)
	}
	if events[1].Level != "info" || events[1].Type != "http_stats" {
		t.Fatalf("event = %+v, want info http_stats", events[1])
	}
	if got := events[1].Message; got != "Top Status Codes:\n  200: 2\n  404: 1" {
		t.Fatalf("event message = %q, want multiline http stats block", got)
	}
}

func TestStreamCommandOutputCapturesAutomaticFingerprintInfo(t *testing.T) {
	t.Parallel()

	state, err := NewState(104, "task-104", "runtime-task", 1, t.TempDir())
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	input := strings.NewReader("[INF] https://example.com 已完成自动指纹识别：nginx, php\n")
	StreamCommandOutputWithResultHandler(input, state, "stdout", true, nil)

	events := state.EventsSince(0, 10).Events
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one automatic fingerprint info event", events)
	}
	if events[0].Level != "info" || events[0].Type != "stdout" {
		t.Fatalf("event = %+v, want info stdout event", events[0])
	}
	if events[0].Message != "https://example.com 已完成自动指纹识别：nginx, php" {
		t.Fatalf("event message = %q, want automatic fingerprint tags message", events[0].Message)
	}
}

func TestTrimAutomaticFingerprintMessageRequiresTarget(t *testing.T) {
	t.Parallel()

	if got := trimAutomaticFingerprintMessage("[INF] 已完成自动指纹识别：nginx"); got != "" {
		t.Fatalf("trimAutomaticFingerprintMessage() = %q, want empty message without target", got)
	}
}

func TestAppendHTTPStatsMergesWithPreviousRunTotals(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	runtimeDir := filepath.Join(rootDir, "data", "runtime")
	taskDir := filepath.Join(runtimeDir, "103")
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	events := []TaskLogEvent{
		{Seq: 1, Level: "info", Type: "task_started", Message: "扫描任务开始执行"},
		{Seq: 2, Level: "info", Type: "http_stats", Message: "Top Status Codes:\n  200: 185\n  405: 76\n  307: 1"},
		{Seq: 3, Level: "info", Type: "task_resume_requested", Message: "扫描任务恢复执行"},
	}
	writeTaskLogEvents(t, filepath.Join(taskDir, "events.jsonl"), events)

	state, err := NewState(103, "task-103", "runtime-task", 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	state.AppendHTTPStats(map[string]int{
		"200": 176,
		"405": 91,
		"400": 1,
	})

	logs := state.EventsSince(0, 10).Events
	if len(logs) != 4 {
		t.Fatalf("events = %+v, want 4", logs)
	}
	if got := logs[3].Message; got != "Top Status Codes:\n  200: 361\n  405: 167\n  307: 1\n  400: 1" {
		t.Fatalf("merged http stats = %q, want cumulative total", got)
	}
}

func TestFormatJSONResultMessage(t *testing.T) {
	t.Parallel()

	payload := map[string]interface{}{
		"template-id":  "http-missing-security-headers",
		"matcher-name": "strict-transport-security",
		"matched-at":   "http://10.107.71.65:8889/",
		"info": map[string]interface{}{
			"name":     "HTTP 安全响应头缺失",
			"severity": "info",
		},
	}

	got := FormatJSONResultMessage(payload)
	want := "[HTTP 安全响应头缺失][info][strict-transport-security] 命中 http://10.107.71.65:8889/"
	if got != want {
		t.Fatalf("FormatJSONResultMessage() = %q, want %q", got, want)
	}
}

func TestFormatJSONResultMessageWithExtractorName(t *testing.T) {
	t.Parallel()

	payload := map[string]interface{}{
		"template-id":    "deprecated-tls",
		"extractor-name": "tls_1.1",
		"extracted-results": []interface{}{
			"tls11",
		},
		"host": "ct-xray.dxmkj01-int.com:443",
		"info": map[string]interface{}{
			"name":     "弃用 TLS/SSL 协议检测（证书安全）",
			"severity": "info",
		},
	}

	got := FormatJSONResultMessage(payload)
	want := "[弃用 TLS/SSL 协议检测（证书安全）][info][tls_1.1] 命中 ct-xray.dxmkj01-int.com:443\nextracted-results：tls11"
	if got != want {
		t.Fatalf("FormatJSONResultMessageWithExtractorName() = %q, want %q", got, want)
	}
}

func TestFormatJSONResultMessageWithExtractedResultsOnly(t *testing.T) {
	t.Parallel()

	payload := map[string]interface{}{
		"template-id": "tls-version",
		"host":        "anquan.duxiaoman-int.com:443",
		"extracted-results": []interface{}{
			"tls12",
			"tls13",
		},
		"info": map[string]interface{}{
			"name":     "TLS 版本识别（证书安全）",
			"severity": "info",
		},
	}

	got := FormatJSONResultMessage(payload)
	want := "[TLS 版本识别（证书安全）][info] 命中 anquan.duxiaoman-int.com:443\nextracted-results：tls12, tls13"
	if got != want {
		t.Fatalf("FormatJSONResultMessageWithExtractedResultsOnly() = %q, want %q", got, want)
	}
}

func TestFormatJSONResultMessageFallback(t *testing.T) {
	t.Parallel()

	payload := map[string]interface{}{
		"template-id": "http-missing-security-headers",
		"host":        "http://10.107.71.65:8889/",
		"info": map[string]interface{}{
			"severity": "medium",
		},
	}

	got := FormatJSONResultMessage(payload)
	want := "[http-missing-security-headers][medium] 命中 http://10.107.71.65:8889/"
	if got != want {
		t.Fatalf("FormatJSONResultMessageFallback() = %q, want %q", got, want)
	}
}

func TestHandleJSONResultLineDeduplicatesRepeatedMatches(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	state, err := NewState(34, "task-34", "demo", 1, dir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	line := `{"template-id":"http-missing-security-headers","matcher-name":"strict-transport-security","matched-at":"http://10.107.71.65:8889/","info":{"name":"HTTP 安全响应头缺失","severity":"info"}}`
	if !HandleJSONResultLine(line, state) {
		t.Fatalf("HandleJSONResultLine() = false, want true")
	}
	if !HandleJSONResultLine(line, state) {
		t.Fatalf("HandleJSONResultLine() duplicate = false, want true")
	}

	summary := state.SnapshotResultSummary()
	if summary.InfoCount != 1 {
		t.Fatalf("InfoCount = %d, want 1", summary.InfoCount)
	}
	progress := state.SnapshotProgress()
	if progress.Matched != 1 {
		t.Fatalf("Matched = %d, want 1", progress.Matched)
	}

	state.Close()
	data, err := os.ReadFile(filepath.Join(dir, "34", "match.log"))
	if err != nil {
		t.Fatalf("ReadFile(match.log) error = %v", err)
	}
	if got := bytes.Count(data, []byte{'\n'}); got != 1 {
		t.Fatalf("match.log lines = %d, want 1", got)
	}
}

func TestHandleJSONResultLineCallsResultHandlerForNewMatchesOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	state, err := NewState(36, "task-36", "demo", 1, dir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	calls := 0
	handler := func(payload map[string]interface{}) {
		calls++
		if payload["template-id"] != "http-missing-security-headers" {
			t.Fatalf("template-id = %v, want http-missing-security-headers", payload["template-id"])
		}
	}
	line := `{"template-id":"http-missing-security-headers","matcher-name":"strict-transport-security","matched-at":"http://10.107.71.65:8889/","info":{"name":"HTTP 安全响应头缺失","severity":"info"}}`
	if !HandleJSONResultLineWithResultHandler(line, state, handler) {
		t.Fatalf("HandleJSONResultLineWithResultHandler() = false, want true")
	}
	if !HandleJSONResultLineWithResultHandler(line, state, handler) {
		t.Fatalf("HandleJSONResultLineWithResultHandler() duplicate = false, want true")
	}
	if calls != 1 {
		t.Fatalf("result handler calls = %d, want 1", calls)
	}
}

func TestHandleJSONResultLineSkipsMatcherStatusFailures(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	state, err := NewState(38, "task-38", "demo", 1, dir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	calls := 0
	handler := func(payload map[string]interface{}) {
		calls++
	}
	line := `{"template-id":"http-missing-security-headers","matcher-name":"strict-transport-security","matched-at":"http://10.107.71.65:8889/","matcher-status":false,"info":{"name":"HTTP 安全响应头缺失","severity":"info"}}`
	if !HandleJSONResultLineWithResultHandler(line, state, handler) {
		t.Fatalf("HandleJSONResultLineWithResultHandler() = false, want true")
	}
	if calls != 0 {
		t.Fatalf("result handler calls = %d, want 0 for matcher failure", calls)
	}

	summary := state.SnapshotResultSummary()
	if summary.InfoCount != 0 || summary.HighCount != 0 || summary.TechCount != 0 {
		t.Fatalf("unexpected result summary for matcher failure: %+v", summary)
	}
	progress := state.SnapshotProgress()
	if progress.Matched != 0 {
		t.Fatalf("Matched = %d, want 0 for matcher failure", progress.Matched)
	}

	page := state.EventsSince(0, 10)
	if len(page.Events) != 1 {
		t.Fatalf("events len = %d, want 1: %+v", len(page.Events), page.Events)
	}
	if page.Events[0].Level != "info" || page.Events[0].Type != "match_failure" {
		t.Fatalf("unexpected failure event: %+v", page.Events[0])
	}
	if page.Events[0].Message != "[HTTP 安全响应头缺失][info][strict-transport-security] 匹配失败 http://10.107.71.65:8889/" {
		t.Fatalf("failure message = %q", page.Events[0].Message)
	}

	state.Close()
	data, err := os.ReadFile(filepath.Join(dir, "38", "match.log"))
	if err != nil {
		t.Fatalf("ReadFile(match.log) error = %v", err)
	}
	if len(bytes.TrimSpace(data)) != 0 {
		t.Fatalf("match.log should be empty for matcher failure: %s", string(data))
	}
}

func TestHandleJSONResultLineCountsFingerprintTagsAsFingerprint(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		tag  string
	}{
		{name: "tech", tag: "tech"},
		{name: "detect", tag: "detect"},
		{name: "favicon", tag: "favicon"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			state, err := NewState(37, "task-37", "demo", 1, dir)
			if err != nil {
				t.Fatalf("NewState() error = %v", err)
			}
			defer state.Close()

			line := `{"template-id":"nginx-detect","matched-at":"http://example.com/","info":{"name":"Nginx Detect","severity":"info","tags":["web","` + tc.tag + `"]}}`
			if !HandleJSONResultLine(line, state) {
				t.Fatalf("HandleJSONResultLine() = false, want true")
			}

			summary := state.SnapshotResultSummary()
			if summary.TechCount != 1 {
				t.Fatalf("TechCount = %d, want 1", summary.TechCount)
			}
			if summary.InfoCount != 0 {
				t.Fatalf("InfoCount = %d, want 0", summary.InfoCount)
			}

			state.Close()
			summary, ok, err := ReadResultSummaryFromMatchLog(filepath.Join(dir, "37", "match.log"), 1)
			if err != nil {
				t.Fatalf("ReadResultSummaryFromMatchLog() error = %v", err)
			}
			if !ok {
				t.Fatalf("ReadResultSummaryFromMatchLog() ok = false, want true")
			}
			if summary.TechCount != 1 || summary.InfoCount != 0 {
				t.Fatalf("unexpected match log summary: %+v", summary)
			}
		})
	}
}

func TestNewStateLoadsExistingMatchKeysForResumeDeduplication(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	state, err := NewState(35, "task-35", "demo", 1, dir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}

	line := `{"template-id":"http-missing-security-headers","matcher-name":"strict-transport-security","matched-at":"http://10.107.71.65:8889/","info":{"name":"HTTP 安全响应头缺失","severity":"info"}}`
	if !HandleJSONResultLine(line, state) {
		t.Fatalf("HandleJSONResultLine() = false, want true")
	}
	state.Close()

	resumed, err := NewState(35, "task-35", "demo", 1, dir)
	if err != nil {
		t.Fatalf("NewState() resumed error = %v", err)
	}
	defer resumed.Close()

	if !HandleJSONResultLine(line, resumed) {
		t.Fatalf("HandleJSONResultLine() duplicate after resume = false, want true")
	}
	summary := resumed.SnapshotResultSummary()
	if summary.InfoCount != 0 {
		t.Fatalf("InfoCount = %d, want 0 for duplicate after resume", summary.InfoCount)
	}
}

func TestReadResultSummaryFromMatchLogDeduplicatesMatches(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "match.log")
	now := time.Now()
	events := []TaskLogEvent{
		{Seq: 1, Time: now, Level: "match", Type: "result", Message: "[HTTP 安全响应头缺失][info][strict-transport-security] 命中 http://example.com/"},
		{Seq: 2, Time: now, Level: "match", Type: "result", Message: "[HTTP 安全响应头缺失][info][strict-transport-security] 命中 http://example.com/"},
		{Seq: 3, Time: now, Level: "match", Type: "result", Message: "[任意文件读取][high] 命中 http://example.com/"},
		{Seq: 4, Time: now, Level: "match", Type: "result", Message: "[Nginx Detect][info] 命中 http://example.com/", Tags: []string{"detect"}},
	}
	writeTaskLogEvents(t, path, events)

	summary, ok, err := ReadResultSummaryFromMatchLog(path, 2)
	if err != nil {
		t.Fatalf("ReadResultSummaryFromMatchLog() error = %v", err)
	}
	if !ok {
		t.Fatalf("ReadResultSummaryFromMatchLog() ok = false, want true")
	}
	if summary.InfoCount != 1 || summary.HighCount != 1 || summary.TechCount != 1 {
		t.Fatalf("unexpected summary counts: %+v", summary)
	}
	if summary.TargetCount != 2 {
		t.Fatalf("TargetCount = %d, want 2", summary.TargetCount)
	}
}

func TestHandleStatsJSONLineAccumulatesResumeSessionRequests(t *testing.T) {
	t.Parallel()

	state := &State{
		progress: TaskProgressSnapshot{
			TotalRequests: 100,
			Requests:      30,
			Percent:       40,
		},
		completedRequests: 40,
	}

	if !HandleStatsJSONLine(`{"requests":"5","actual_requests":"3","total":"100","percent":"5","matched":"9"}`, state) {
		t.Fatalf("HandleStatsJSONLine() = false, want true")
	}
	progress := state.SnapshotProgress()
	if progress.Requests != 33 {
		t.Fatalf("Requests = %d, want cumulative actual requests 33", progress.Requests)
	}
	if progress.TotalRequests != 100 {
		t.Fatalf("TotalRequests = %d, want 100", progress.TotalRequests)
	}
	if progress.Percent != 45 {
		t.Fatalf("Percent = %v, want cumulative logical percent 45", progress.Percent)
	}
	if progress.Matched != 0 {
		t.Fatalf("Matched = %d, want result-event based matched count 0", progress.Matched)
	}

	if !HandleStatsJSONLine(`{"requests":"8","actual_requests":"4","total":"100","percent":"8"}`, state) {
		t.Fatalf("HandleStatsJSONLine() second = false, want true")
	}
	progress = state.SnapshotProgress()
	if progress.Requests != 34 {
		t.Fatalf("Requests after second stats = %d, want 34", progress.Requests)
	}
	if progress.Percent != 48 {
		t.Fatalf("Percent after second stats = %v, want 48", progress.Percent)
	}
}

func TestAppendEventWritesMatchLog(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	state, err := NewState(33, "task-33", "demo", 1, dir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer state.Close()

	state.Append("match", "result", "[demo][info] 命中 http://example.com")
	state.Append("info", "progress", "扫描进度更新")
	state.Close()

	data, err := os.ReadFile(filepath.Join(dir, "33", "match.log"))
	if err != nil {
		t.Fatalf("ReadFile(match.log) error = %v", err)
	}

	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("match.log lines = %d, want 1", lines)
	}
	if !bytes.Contains(data, []byte(`"level":"match"`)) {
		t.Fatalf("match.log does not contain match event: %s", string(data))
	}
	if bytes.Contains(data, []byte(`"level":"info"`)) {
		t.Fatalf("match.log should not contain info event: %s", string(data))
	}
}

func TestRecordResultCountsTechTagAsTech(t *testing.T) {
	t.Parallel()

	state := &State{}
	state.RecordResult("tech-template", "Nginx", "info", []string{"web", "tech"})

	summary := state.SnapshotResultSummary()
	if summary.TechCount != 1 {
		t.Fatalf("TechCount = %d, want 1", summary.TechCount)
	}
	if summary.InfoCount != 0 {
		t.Fatalf("InfoCount = %d, want 0", summary.InfoCount)
	}
}

func TestRecordResultDoesNotUseFingerprintNameAsTech(t *testing.T) {
	t.Parallel()

	state := &State{}
	state.RecordResult("fingerprint-template", "Nginx 指纹识别", "info", nil)

	summary := state.SnapshotResultSummary()
	if summary.TechCount != 0 {
		t.Fatalf("TechCount = %d, want 0", summary.TechCount)
	}
	if summary.InfoCount != 1 {
		t.Fatalf("InfoCount = %d, want 1", summary.InfoCount)
	}
}

func TestRecordResultCountsVulnerabilityBySeverity(t *testing.T) {
	t.Parallel()

	state := &State{}
	state.RecordResult("vuln-template", "HTTP 安全响应头缺失", "info", nil)
	state.RecordResult("high-template", "任意文件读取", "high", nil)

	summary := state.SnapshotResultSummary()
	if summary.InfoCount != 1 {
		t.Fatalf("InfoCount = %d, want 1", summary.InfoCount)
	}
	if summary.HighCount != 1 {
		t.Fatalf("HighCount = %d, want 1", summary.HighCount)
	}
	if summary.TechCount != 0 {
		t.Fatalf("TechCount = %d, want 0", summary.TechCount)
	}
}

func TestSnapshotResultSummaryIncludesRequestStats(t *testing.T) {
	t.Parallel()

	state := &State{TargetCount: 2}
	state.progress.TotalRequests = 120
	state.progress.Requests = 88

	summary := state.SnapshotResultSummary()
	if summary.TotalRequests != 120 {
		t.Fatalf("TotalRequests = %d, want 120", summary.TotalRequests)
	}
	if summary.RealRequests != 88 {
		t.Fatalf("RealRequests = %d, want 88", summary.RealRequests)
	}
	if summary.TargetCount != 2 {
		t.Fatalf("TargetCount = %d, want 2", summary.TargetCount)
	}
}

func writeTaskLogEvents(t *testing.T, path string, events []TaskLogEvent) {
	t.Helper()

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}

	for _, event := range events {
		encoded, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			_ = file.Close()
			t.Fatalf("Marshal() error = %v", marshalErr)
		}
		if _, writeErr := file.Write(append(encoded, '\n')); writeErr != nil {
			_ = file.Close()
			t.Fatalf("Write() error = %v", writeErr)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
