package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type dedupBlockingHandler struct {
	started chan struct{}
	release chan struct{}
}

func (h *dedupBlockingHandler) Type() string                   { return "test.sync" }
func (h *dedupBlockingHandler) Validate(json.RawMessage) error { return nil }
func (h *dedupBlockingHandler) Execute(ctx context.Context, _ entity.ScheduledJob, _ entity.ScheduledJobRun, _ ProgressReporter) error {
	h.started <- struct{}{}
	select {
	case <-h.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newSchedulerDedupTest(t *testing.T, policy string) (*gorm.DB, repository.ScheduledJobRepository, repository.ScheduledJobRunRepository, entity.ScheduledJob) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "scheduled_runs.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	// SQLite 不支持 FOR UPDATE；单连接让测试事务串行，生产 MySQL 由任务行锁串行。
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&entity.ScheduledJob{}, &entity.ScheduledJobRun{}); err != nil {
		t.Fatal(err)
	}
	jobs := repository.NewScheduledJobRepository(db)
	job := entity.ScheduledJob{Name: "test", JobType: "test.sync", CronExpr: "0 */2 * * *", Timezone: "Asia/Shanghai", Enabled: true, ConfigJSON: "{}", ConcurrencyPolicy: policy, TimeoutSeconds: 60}
	if err := jobs.Create(context.Background(), &job); err != nil {
		t.Fatal(err)
	}
	return db, jobs, repository.NewScheduledJobRunRepository(db), job
}

func waitSchedulerRunStatus(t *testing.T, runs repository.ScheduledJobRunRepository, id int64, status string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		run, err := runs.FindByID(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if run.Status == status {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("run %d status = %s, want %s", id, run.Status, status)
		case <-ticker.C:
		}
	}
}

func TestSchedulerDedupConcurrentTriggersReuseRun(t *testing.T) {
	for _, policy := range []string{"forbid", "allow"} {
		t.Run(policy, func(t *testing.T) {
			db, jobs, runs, job := newSchedulerDedupTest(t, policy)
			handler := &dedupBlockingHandler{started: make(chan struct{}, 16), release: make(chan struct{})}
			registry := NewJobHandlerRegistry()
			if err := registry.Register(handler); err != nil {
				t.Fatal(err)
			}
			managers := []*schedulerManager{
				NewSchedulerManager(jobs, runs, registry, nil).(*schedulerManager),
				NewSchedulerManager(jobs, runs, registry, nil).(*schedulerManager),
			}
			t.Cleanup(func() {
				close(handler.release)
				for _, manager := range managers {
					manager.StopJob(context.Background(), job.ID)
				}
			})
			firedAt := time.Date(2026, 11, 26, 2, 0, 0, 0, time.FixedZone("CST", 8*60*60))
			first, err := managers[0].trigger(context.Background(), job.ID, "schedule", firedAt)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-handler.started:
			case <-time.After(3 * time.Second):
				t.Fatal("scheduled handler did not start")
			}
			var wg sync.WaitGroup
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					triggerType := "manual"
					if i%2 == 0 {
						triggerType = "schedule"
					}
					run, err := managers[i%2].trigger(context.Background(), job.ID, triggerType, firedAt.Add(2*time.Hour))
					if err != nil {
						t.Errorf("duplicate trigger: %v", err)
					} else if run.ID != first.ID {
						t.Errorf("duplicate run ID = %d, want %d", run.ID, first.ID)
					}
				}(i)
			}
			wg.Wait()
			var count int64
			if err := db.Model(&entity.ScheduledJobRun{}).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 1 || len(handler.started) != 0 {
				t.Fatalf("records = %d, extra executions = %d, want 1 and 0", count, len(handler.started))
			}
			managers[0].StopJob(context.Background(), job.ID)
			waitSchedulerRunStatus(t, runs, first.ID, ScheduledJobStatusCancel)
		})
	}
}

func TestSchedulerDedupConcurrentFirstTrigger(t *testing.T) {
	db, jobs, runs, job := newSchedulerDedupTest(t, "allow")
	handler := &dedupBlockingHandler{started: make(chan struct{}, 16), release: make(chan struct{})}
	registry := NewJobHandlerRegistry()
	if err := registry.Register(handler); err != nil {
		t.Fatal(err)
	}
	managers := []*schedulerManager{
		NewSchedulerManager(jobs, runs, registry, nil).(*schedulerManager),
		NewSchedulerManager(jobs, runs, registry, nil).(*schedulerManager),
	}
	t.Cleanup(func() { close(handler.release) })
	start := make(chan struct{})
	ids := make(chan int64, 16)
	var wg sync.WaitGroup
	firedAt := time.Now().Truncate(time.Hour)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			triggerType := "schedule"
			if i%3 == 0 {
				triggerType = "manual"
			}
			run, err := managers[i%2].trigger(context.Background(), job.ID, triggerType, firedAt)
			if err != nil {
				t.Errorf("concurrent first trigger: %v", err)
				return
			}
			ids <- run.ID
		}(i)
	}
	close(start)
	wg.Wait()
	close(ids)
	var firstID int64
	for id := range ids {
		if firstID == 0 {
			firstID = id
		} else if id != firstID {
			t.Errorf("run ID = %d, want %d", id, firstID)
		}
	}
	var count int64
	if err := db.Model(&entity.ScheduledJobRun{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("records = %d, %v, want 1", count, err)
	}
	select {
	case <-handler.started:
	case <-time.After(3 * time.Second):
		t.Fatal("scheduled handler did not start")
	}
	for _, manager := range managers {
		manager.StopJob(context.Background(), job.ID)
	}
	waitSchedulerRunStatus(t, runs, firstID, ScheduledJobStatusCancel)
	if len(handler.started) != 0 {
		t.Fatalf("extra executions = %d, want 0", len(handler.started))
	}
}

func TestSchedulerDedupDifferentJobsRunIndependently(t *testing.T) {
	_, jobs, runs, job := newSchedulerDedupTest(t, "forbid")
	ctx := context.Background()
	original := entity.ScheduledJobRun{JobID: job.ID, TriggerType: "manual", FireKey: "original", Status: ScheduledJobStatusRunning}
	if err := runs.Create(ctx, &original); err != nil {
		t.Fatal(err)
	}
	other := job
	other.ID = 0
	if err := jobs.Create(ctx, &other); err != nil {
		t.Fatal(err)
	}
	manager := NewSchedulerManager(jobs, runs, nil, nil)
	run, err := manager.Trigger(ctx, other.ID, "manual")
	if err != nil || run.ID == original.ID || run.JobID != other.ID {
		t.Fatalf("other job trigger = %+v, %v, want new independent record", run, err)
	}
	waitSchedulerRunStatus(t, runs, run.ID, ScheduledJobStatusFailed)
}

func TestSchedulerDedupCompletedScheduleIsNotRepeated(t *testing.T) {
	for _, status := range []string{ScheduledJobStatusQueued, ScheduledJobStatusRunning, ScheduledJobStatusSuccess, ScheduledJobStatusFailed, ScheduledJobStatusTimeout, ScheduledJobStatusCancel} {
		t.Run(status, func(t *testing.T) {
			db, jobs, runs, job := newSchedulerDedupTest(t, "allow")
			ctx := context.Background()
			firedAt := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
			original := entity.ScheduledJobRun{JobID: job.ID, TriggerType: "schedule", FireKey: fmt.Sprintf("schedule:%d:%d", job.ID, firedAt.Unix()), Status: status}
			if err := runs.Create(ctx, &original); err != nil {
				t.Fatal(err)
			}
			manager := NewSchedulerManager(jobs, runs, nil, nil).(*schedulerManager)
			duplicate, err := manager.trigger(ctx, job.ID, "schedule", firedAt.In(time.FixedZone("CST", 8*60*60)))
			if err != nil || duplicate.ID != original.ID || duplicate.Status != status {
				t.Fatalf("duplicate = %+v, %v, want original %+v", duplicate, err, original)
			}
			var count int64
			if err := db.Model(&entity.ScheduledJobRun{}).Count(&count).Error; err != nil || count != 1 {
				t.Fatalf("records = %d, %v, want 1", count, err)
			}
		})
	}
}

func TestSchedulerDedupAllowsNextScheduleAndManualRetry(t *testing.T) {
	_, jobs, runs, job := newSchedulerDedupTest(t, "forbid")
	ctx := context.Background()
	firedAt := time.Now().Truncate(time.Hour)
	original := entity.ScheduledJobRun{JobID: job.ID, TriggerType: "schedule", FireKey: fmt.Sprintf("schedule:%d:%d", job.ID, firedAt.Unix()), Status: ScheduledJobStatusFailed}
	if err := runs.Create(ctx, &original); err != nil {
		t.Fatal(err)
	}
	manager := NewSchedulerManager(jobs, runs, nil, nil).(*schedulerManager)
	for _, triggerType := range []string{"schedule", "manual"} {
		run, err := manager.trigger(ctx, job.ID, triggerType, firedAt.Add(2*time.Hour))
		if err != nil || run.ID == original.ID {
			t.Fatalf("new %s run = %+v, %v", triggerType, run, err)
		}
		// 未注册处理器使新任务快速结束，验证实际启动而非仅创建记录。
		waitSchedulerRunStatus(t, runs, run.ID, ScheduledJobStatusFailed)
		original = *run
	}
}

type failingScheduledRunRepository struct {
	repository.ScheduledJobRunRepository
	err error
}

func (r *failingScheduledRunRepository) WithJobLock(context.Context, int64, func(repository.ScheduledJobRunRepository) error) error {
	return r.err
}

func TestSchedulerDedupLockFailureDoesNotExecute(t *testing.T) {
	_, jobs, _, job := newSchedulerDedupTest(t, "allow")
	wantErr := errors.New("database unavailable")
	runs := &failingScheduledRunRepository{err: wantErr}
	manager := NewSchedulerManager(jobs, runs, nil, nil).(*schedulerManager)
	run, err := manager.Trigger(context.Background(), job.ID, "manual")
	if run != nil || !errors.Is(err, wantErr) || len(manager.runCancels) != 0 {
		t.Fatalf("trigger = %+v, %v, active runs = %d", run, err, len(manager.runCancels))
	}
}

func TestSchedulerDedupAppliesToAllJobTypes(t *testing.T) {
	for _, jobType := range []string{"cve_file_names.sync", "vulnx_vulnerability.sync", "chaitin_vulnerability.sync", "aliyun_avd_vulnerability.sync", VulnerabilityIncrementalJobType, "custom.sync"} {
		for _, policy := range []string{"forbid", "allow"} {
			t.Run(jobType+"/"+policy, func(t *testing.T) {
				db, jobs, runs, job := newSchedulerDedupTest(t, policy)
				ctx := context.Background()
				job.JobType = jobType
				if err := jobs.Update(ctx, &job); err != nil {
					t.Fatal(err)
				}
				original := entity.ScheduledJobRun{JobID: job.ID, TriggerType: "manual", FireKey: "original", Status: ScheduledJobStatusQueued}
				if err := runs.Create(ctx, &original); err != nil {
					t.Fatal(err)
				}
				manager := NewSchedulerManager(jobs, runs, nil, nil)
				for _, status := range []string{ScheduledJobStatusQueued, ScheduledJobStatusRunning} {
					if err := runs.UpdateFields(ctx, original.ID, map[string]interface{}{"status": status}); err != nil {
						t.Fatal(err)
					}
					for _, triggerType := range []string{"schedule", "manual"} {
						run, err := manager.Trigger(ctx, job.ID, triggerType)
						if err != nil || run.ID != original.ID || run.Status != status {
							t.Fatalf("%s trigger = %+v, %v, want original %s record", triggerType, run, err, status)
						}
					}
				}
				var count int64
				if err := db.Model(&entity.ScheduledJobRun{}).Count(&count).Error; err != nil || count != 1 {
					t.Fatalf("records = %d, %v, want 1", count, err)
				}
			})
		}
	}
}

func TestSchedulerDedupPreservesIncrementalFireKey(t *testing.T) {
	_, jobs, runs, job := newSchedulerDedupTest(t, "forbid")
	ctx := context.Background()
	job.JobType = VulnerabilityIncrementalJobType
	if err := jobs.Update(ctx, &job); err != nil {
		t.Fatal(err)
	}
	firedAt := time.Now().Truncate(time.Hour)
	original := entity.ScheduledJobRun{JobID: job.ID, TriggerType: "schedule", FireKey: fmt.Sprintf("incremental:%d:%d", job.ID, firedAt.Unix()), Status: ScheduledJobStatusSuccess}
	if err := runs.Create(ctx, &original); err != nil {
		t.Fatal(err)
	}
	manager := NewSchedulerManager(jobs, runs, nil, nil).(*schedulerManager)
	run, err := manager.trigger(ctx, job.ID, "schedule", firedAt)
	if err != nil || run.ID != original.ID || run.Status != ScheduledJobStatusSuccess {
		t.Fatalf("existing incremental schedule = %+v, %v, want original success record", run, err)
	}
}
