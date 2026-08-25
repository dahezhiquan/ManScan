package service

import (
	"testing"
	"time"

	"ManScan/server/internal/model/entity"
)

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

func ptr(value string) *string {
	return &value
}
