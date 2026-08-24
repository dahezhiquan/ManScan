package scanruntime

import "testing"

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
			name: "hide tls handshake mismatch scanner errors",
			event: TaskLogEvent{
				Level:   "error",
				Type:    "scanner_error",
				Message: "[CVE-2025-25256][tcp] 10.107.71.65:8889: tls: first record does not look like a TLS handshake",
			},
			want: true,
		},
		{
			name: "hide redis parser mismatch scanner errors",
			event: TaskLogEvent{
				Level:   "error",
				Type:    "scanner_error",
				Message: `[CVE-2025-46817][javascript] 10.107.71.65:8889: cause="redis: can't parse map reply: \"HTTP/1.1 400 Bad Request\""`,
			},
			want: true,
		},
		{
			name: "keep other scanner errors",
			event: TaskLogEvent{
				Level:   "error",
				Type:    "scanner_error",
				Message: "[CVE-2025-99999][tcp] 10.107.71.65:8889: connect: connection refused",
			},
			want: false,
		},
		{
			name: "keep non scanner errors",
			event: TaskLogEvent{
				Level:   "error",
				Type:    "task_failed",
				Message: "扫描任务执行失败",
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
		{Seq: 4, Level: "error", Type: "scanner_error", Message: "[CVE-2025-99999][tcp] 10.107.71.65:8889: connect: connection refused"},
	}

	filtered := FilterFrontendLogEvents(events)
	if len(filtered) != 2 {
		t.Fatalf("FilterFrontendLogEvents() len = %d, want 2", len(filtered))
	}

	if filtered[0].Seq != 1 || filtered[1].Seq != 4 {
		t.Fatalf("FilterFrontendLogEvents() kept unexpected events: %+v", filtered)
	}
}
