package service

import (
	"context"
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

	runningState.RecordResult("runtime-high", "弃用 TLS/SSL 协议检测（证书安全）", "high")
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

func TestStatsIncludesRunningStateSavedRequests(t *testing.T) {
	t.Parallel()

	runtimeDir := t.TempDir()
	runningState, err := scanruntime.NewState(9, "task-9", "running-task", 1, runtimeDir)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	defer runningState.Close()

	runningState.UpdateProgress(func(snapshot *scanruntime.TaskProgressSnapshot) {
		snapshot.TotalRequests = 200
		snapshot.Requests = 125
	})

	svc := &scanTaskService{
		repository: &scanTaskRepositoryStub{
			statsResult: &dto.ScanTaskStats{
				Total:         18,
				Running:       1,
				SavedRequests: 12345,
			},
		},
		states: map[int64]*scanTaskRuntime{
			9: newScanTaskRuntime(runningState),
		},
	}

	stats, err := svc.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}

	if stats.Total != 18 || stats.Running != 1 {
		t.Fatalf("unexpected count stats: %+v", stats)
	}
	if stats.SavedRequests != 12420 {
		t.Fatalf("SavedRequests = %d, want 12420", stats.SavedRequests)
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
	listResult        *dto.PageResult[dto.ScanTaskListItem]
	listAllItems      []dto.ScanTaskListItem
	statsResult       *dto.ScanTaskStats
	tasks             map[int64]*entity.ScanTask
	findByIDErr       error
	updateStatusErr   error
	updateStatusCalls []statusUpdateCall
}

func (s *scanTaskRepositoryStub) Create(_ context.Context, _ *entity.ScanTask) error {
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

func ptr(value string) *string {
	return &value
}
