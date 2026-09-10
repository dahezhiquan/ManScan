package progress

import (
	"testing"

	"github.com/projectdiscovery/clistats"
)

func TestMetricsMapOmitsUnknownTotalAndPercent(t *testing.T) {
	stats, err := clistats.New()
	if err != nil {
		t.Fatalf("clistats.New() error = %v", err)
	}
	stats.AddCounter("requests", 7)
	stats.AddCounter("actual_requests", 6)
	stats.AddCounter("total", 0)
	stats.AddCounter("total_known", 0)
	stats.AddCounter("matched", 0)
	stats.AddCounter("errors", 0)

	metrics := metricsMap(stats)
	if _, ok := metrics["total"]; ok {
		t.Fatalf("metricsMap() returned total before it was known")
	}
	if _, ok := metrics["percent"]; ok {
		t.Fatalf("metricsMap() returned percent before total was known")
	}
	if got := metrics["total_known"]; got != "0" {
		t.Fatalf("total_known = %v, want 0", got)
	}

	stats.IncrementCounter("total", 20)
	stats.IncrementCounter("total_known", 1)
	metrics = metricsMap(stats)
	if got := metrics["total"]; got != "20" {
		t.Fatalf("total = %v, want 20", got)
	}
	if got := metrics["percent"]; got != "35" {
		t.Fatalf("percent = %v, want 35", got)
	}
}

func TestCalculateProgressPercentWithUnknownTotal(t *testing.T) {
	if got := calculateProgressPercent(7, 0); got != 0 {
		t.Fatalf("calculateProgressPercent(7, 0) = %d, want 0", got)
	}
}

func TestStatsTickerPublishesTemplateCount(t *testing.T) {
	progressClient, err := NewStatsTicker(0, false, false, false, 0)
	if err != nil {
		t.Fatalf("NewStatsTicker() error = %v", err)
	}

	ticker := progressClient.(*StatsTicker)
	ticker.Init(1, 0, 0)
	ticker.SetTemplateCount(12)

	metrics := metricsMap(ticker.stats)
	if got := metrics["templates"]; got != "12" {
		t.Fatalf("templates = %v, want 12", got)
	}

	// Template counts are monotonic to remain safe after clistats starts.
	ticker.SetTemplateCount(5)
	metrics = metricsMap(ticker.stats)
	if got := metrics["templates"]; got != "12" {
		t.Fatalf("templates after a lower update = %v, want 12", got)
	}
}
