package stats

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestTrackErrorKind(t *testing.T) {
	tracker := NewTracker()

	// Test single increment
	tracker.TrackErrorKind("timeout")
	if count, _ := tracker.errorCodes.Get("timeout"); count == nil || count.Load() != 1 {
		t.Errorf("expected error kind timeout count to be 1, got %v", count)
	}

	// Test multiple increments
	tracker.TrackErrorKind("timeout")
	if count, _ := tracker.errorCodes.Get("timeout"); count == nil || count.Load() != 2 {
		t.Errorf("expected error kind timeout count to be 2, got %v", count)
	}

	// Test different error kind
	tracker.TrackErrorKind("connection-refused")
	if count, _ := tracker.errorCodes.Get("connection-refused"); count == nil || count.Load() != 1 {
		t.Errorf("expected error kind connection-refused count to be 1, got %v", count)
	}
}

func TestTrackWaf_Detect(t *testing.T) {
	tracker := NewTracker()

	tracker.TrackWAFDetected("Attention Required! | Cloudflare")
	if count, _ := tracker.wafDetected.Get("cloudflare"); count == nil || count.Load() != 1 {
		t.Errorf("expected waf detected count to be 1, got %v", count)
	}
}

func TestDisplayTopStatsUsesInfoPrefix(t *testing.T) {
	tracker := NewTracker()
	tracker.TrackStatusCode("200")
	tracker.TrackStatusCode("200")
	tracker.TrackStatusCode("404")

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	tracker.DisplayTopStats(true)

	_ = w.Close()
	output := <-done

	if !strings.Contains(output, "[INF] Top Status Codes:") {
		t.Fatalf("DisplayTopStats() output = %q, want info-prefixed status summary", output)
	}
	if !strings.Contains(output, "[INF]   200: 2") {
		t.Fatalf("DisplayTopStats() output = %q, want 200 counter", output)
	}
}
