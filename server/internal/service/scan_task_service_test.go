package service

import (
	"fmt"
	"testing"

	"ManScan/server/internal/model/dto"
)

func TestNormalizeCreateTaskRequestAllowsLargeTargetSets(t *testing.T) {
	targets := make([]string, 2001)
	for i := range targets {
		targets[i] = fmt.Sprintf("https://example-%d.com", i)
	}

	plan, err := normalizeCreateTaskRequest(dto.CreateScanTaskRequest{
		Targets: targets,
	})
	if err != nil {
		t.Fatalf("normalizeCreateTaskRequest returned error: %v", err)
	}
	if got, want := len(plan.CollectedTargets), len(targets); got != want {
		t.Fatalf("CollectedTargets length = %d, want %d", got, want)
	}
}
