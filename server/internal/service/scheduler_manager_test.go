package service

import (
	"context"
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

type nextRunRepository struct {
	repository.ScheduledJobRunRepository
}

func (r *nextRunRepository) HasRunning(context.Context, int64) (bool, error) {
	// 模拟触发失败，验证刷新计划不依赖业务执行结果。
	return false, errors.New("execution unavailable")
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
