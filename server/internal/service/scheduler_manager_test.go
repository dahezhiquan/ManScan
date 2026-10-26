package service

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
)

type nextRunJobRepository struct {
	repository.ScheduledJobRepository
	mu      sync.Mutex
	job     entity.ScheduledJob
	updates chan *time.Time
}

func (r *nextRunJobRepository) ListEnabled(context.Context) ([]entity.ScheduledJob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return []entity.ScheduledJob{r.job}, nil
}

func (r *nextRunJobRepository) FindByID(context.Context, int64) (*entity.ScheduledJob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	job := r.job
	return &job, nil
}

func (r *nextRunJobRepository) UpdateNextRunAt(_ context.Context, _ int64, next *time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.job.NextRunAt = next
	r.updates <- next
	return nil
}

func (r *nextRunJobRepository) UpdateRuntime(context.Context, int64, *time.Time, *time.Time, string, string) error {
	return nil
}

func (r *nextRunJobRepository) UpdateEnabled(_ context.Context, _ int64, enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.job.Enabled = enabled
	return nil
}

type nextRunRepository struct {
	repository.ScheduledJobRunRepository
}

func (r *nextRunRepository) HasRunning(context.Context, int64) (bool, error) {
	// 模拟触发失败，验证刷新计划不依赖业务执行结果。
	return false, errors.New("execution unavailable")
}

type cancellableRunRepository struct {
	repository.ScheduledJobRunRepository
	mu   sync.Mutex
	run  entity.ScheduledJobRun
	done chan struct{}
}

func (r *cancellableRunRepository) Create(_ context.Context, run *entity.ScheduledJobRun) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	run.ID = 1
	r.run = *run
	return nil
}

func (r *cancellableRunRepository) HasRunning(context.Context, int64) (bool, error) {
	return false, nil
}

func (r *cancellableRunRepository) UpdateFields(_ context.Context, _ int64, fields map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if value, ok := fields["status"].(string); ok {
		r.run.Status = value
		if value == ScheduledJobStatusCancel {
			select {
			case <-r.done:
			default:
				close(r.done)
			}
		}
	}
	return nil
}

func (r *cancellableRunRepository) snapshot() entity.ScheduledJobRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.run
}

type blockingScheduledJobHandler struct {
	started chan struct{}
}

func (h *blockingScheduledJobHandler) Type() string { return "test.blocking" }

func (h *blockingScheduledJobHandler) Validate(json.RawMessage) error { return nil }

func (h *blockingScheduledJobHandler) Execute(ctx context.Context, _ entity.ScheduledJob, _ entity.ScheduledJobRun, _ ProgressReporter) error {
	close(h.started)
	<-ctx.Done()
	return ctx.Err()
}

func newNextRunTestManager(t *testing.T, cronExpr string) (*schedulerManager, *nextRunJobRepository) {
	t.Helper()
	jobs := &nextRunJobRepository{
		job: entity.ScheduledJob{
			ID: 1, Name: "test", JobType: "test.sync", CronExpr: cronExpr,
			Timezone: "Asia/Shanghai", Enabled: true, ConfigJSON: "{}", ConcurrencyPolicy: "forbid",
		},
		updates: make(chan *time.Time, 16),
	}
	manager := NewSchedulerManager(jobs, &nextRunRepository{}, nil, nil).(*schedulerManager)
	t.Cleanup(func() {
		if err := manager.Stop(context.Background()); err != nil {
			t.Errorf("stop scheduler: %v", err)
		}
	})
	return manager, jobs
}

func TestSchedulerNextRunAtStartup(t *testing.T) {
	manager, jobs := newNextRunTestManager(t, "0 0 * * *")
	stale := time.Now().Add(-24 * time.Hour)
	jobs.job.NextRunAt = &stale
	before := time.Now()
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := <-jobs.updates
	if next == nil || !next.After(before) {
		t.Fatalf("startup next run = %v, want future time", next)
	}
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	localNext := next.In(location)
	if localNext.Hour() != 0 || localNext.Minute() != 0 || localNext.Second() != 0 {
		t.Fatalf("next run = %v, want midnight in Asia/Shanghai", localNext)
	}
}

func TestSchedulerNextRunAtAutomaticTrigger(t *testing.T) {
	manager, jobs := newNextRunTestManager(t, "@every 1s")
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	initial := <-jobs.updates
	select {
	case next := <-jobs.updates:
		if initial == nil || next == nil || !next.After(*initial) {
			t.Fatalf("automatic trigger next run = %v, want after %v", next, initial)
		}
		entry := manager.cron.Entry(manager.entries[1])
		if !next.Equal(entry.Next) {
			t.Fatalf("persisted next run = %v, cron next = %v", next, entry.Next)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("automatic trigger did not refresh next run")
	}
}

func TestSchedulerNextRunAtScheduleChangeAndDisable(t *testing.T) {
	manager, jobs := newNextRunTestManager(t, "0 0 * * *")
	ctx := context.Background()
	if err := manager.AddOrUpdate(ctx, 1); err != nil {
		t.Fatal(err)
	}
	<-jobs.updates
	oldEntry := manager.cron.Entry(manager.entries[1])
	jobs.job.CronExpr = "0 12 * * *"
	if err := manager.AddOrUpdate(ctx, 1); err != nil {
		t.Fatal(err)
	}
	updated := <-jobs.updates
	if updated == nil || updated.In(time.FixedZone("CST", 8*60*60)).Hour() != 12 {
		t.Fatalf("updated next run = %v, want noon in Asia/Shanghai", updated)
	}
	// 已排队的旧回调只同步当前计划，不得写回旧计划。
	oldEntry.Job.Run()
	if next := <-jobs.updates; next == nil || !next.Equal(*updated) {
		t.Fatalf("old callback next run = %v, want %v", next, updated)
	}
	jobs.job.Enabled = false
	if err := manager.AddOrUpdate(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if next := <-jobs.updates; next != nil {
		t.Fatalf("disabled next run = %v, want nil", next)
	}
	oldEntry.Job.Run()
	select {
	case next := <-jobs.updates:
		t.Fatalf("removed callback restored next run: %v", next)
	default:
	}
}

func TestSchedulerNextRunAtManualTrigger(t *testing.T) {
	manager, jobs := newNextRunTestManager(t, "0 0 * * *")
	if err := manager.AddOrUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	<-jobs.updates
	_, _ = manager.Trigger(context.Background(), 1, "manual")
	select {
	case next := <-jobs.updates:
		t.Fatalf("manual trigger changed next run: %v", next)
	default:
	}
}

func TestSchedulerStopJobCancelsActiveRun(t *testing.T) {
	jobs := &nextRunJobRepository{job: entity.ScheduledJob{
		ID: 1, Name: "test", JobType: "test.blocking", CronExpr: "0 0 * * *",
		Timezone: "Asia/Shanghai", Enabled: true, ConfigJSON: "{}", ConcurrencyPolicy: "allow",
	}}
	runs := &cancellableRunRepository{done: make(chan struct{})}
	handler := &blockingScheduledJobHandler{started: make(chan struct{})}
	registry := NewJobHandlerRegistry()
	if err := registry.Register(handler); err != nil {
		t.Fatal(err)
	}
	manager := NewSchedulerManager(jobs, runs, registry, nil).(*schedulerManager)
	t.Cleanup(func() { manager.StopJob(context.Background(), 1) })
	_, err := manager.Trigger(context.Background(), 1, "manual")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("job did not start")
	}
	if stopped := manager.StopJob(context.Background(), 1); stopped != 1 {
		t.Fatalf("stopped runs = %d, want 1", stopped)
	}
	select {
	case <-runs.done:
	case <-time.After(time.Second):
		t.Fatal("cancelled job did not finish")
	}
	if run := runs.snapshot(); run.Status != ScheduledJobStatusCancel {
		t.Fatalf("run status = %q, want %q", run.Status, ScheduledJobStatusCancel)
	}
}

func TestScheduledJobControls(t *testing.T) {
	manager, jobs := newNextRunTestManager(t, "0 0 * * *")
	svc := NewScheduledJobService(jobs, nil, manager, nil)
	ctx := context.Background()
	runningCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	otherCtx, otherCancel := context.WithCancel(ctx)
	defer otherCancel()
	manager.registerRun(1, 10, cancel)
	manager.registerRun(2, 20, otherCancel)

	paused, err := svc.Pause(ctx, 1)
	if err != nil || paused.Enabled || paused.NextRunAt != nil {
		t.Fatalf("pause = %+v, error = %v", paused, err)
	}
	if runningCtx.Err() != nil {
		t.Fatal("pause cancelled an active execution")
	}
	resumed, err := svc.Resume(ctx, 1)
	if err != nil || !resumed.Enabled || resumed.NextRunAt == nil || !resumed.NextRunAt.After(time.Now()) {
		t.Fatalf("resume = %+v, error = %v", resumed, err)
	}
	if resumed.CronExpr != "0 0 * * *" || resumed.ConfigJSON != "{}" {
		t.Fatalf("resume changed task configuration: %+v", resumed)
	}
	count, err := svc.Stop(ctx, 1)
	if err != nil || count != 1 || runningCtx.Err() != context.Canceled {
		t.Fatalf("stop count = %d, error = %v, run context = %v", count, err, runningCtx.Err())
	}
	if otherCtx.Err() != nil {
		t.Fatal("stop cancelled another job")
	}
	stopped, err := svc.Get(ctx, 1)
	if err != nil || stopped.Enabled || stopped.NextRunAt != nil {
		t.Fatalf("stopped job = %+v, error = %v", stopped, err)
	}
	if _, err := manager.Trigger(ctx, 1, "schedule"); err == nil {
		t.Fatal("stopped job accepted automatic trigger")
	}
	manager.unregisterRun(1, 10)
	if count, err := svc.Stop(ctx, 1); err != nil || count != 0 {
		t.Fatalf("stop without active runs: count = %d, error = %v", count, err)
	}
	for _, id := range []int64{0, -1} {
		if _, err := svc.Pause(ctx, id); !errors.Is(err, ErrInvalidScheduledJob) {
			t.Fatalf("pause accepted id %d: %v", id, err)
		}
		if _, err := svc.Resume(ctx, id); !errors.Is(err, ErrInvalidScheduledJob) {
			t.Fatalf("resume accepted id %d: %v", id, err)
		}
		if _, err := svc.Stop(ctx, id); !errors.Is(err, ErrInvalidScheduledJob) {
			t.Fatalf("stop accepted id %d: %v", id, err)
		}
	}
}
