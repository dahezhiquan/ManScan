package scanruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
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
