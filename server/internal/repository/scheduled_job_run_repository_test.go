package repository

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestScheduledJobRunRepositoryLockedTransaction(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "runs.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&entity.ScheduledJob{}, &entity.ScheduledJobRun{}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	job := entity.ScheduledJob{Name: "test", JobType: "test.sync", CronExpr: "0 * * * *", ConfigJSON: "{}"}
	if err := NewScheduledJobRepository(db).Create(ctx, &job); err != nil {
		t.Fatal(err)
	}
	runs := NewScheduledJobRunRepository(db)
	rollbackErr := errors.New("rollback requested")
	err = runs.WithJobLock(ctx, job.ID, func(txRuns ScheduledJobRunRepository) error {
		run := &entity.ScheduledJobRun{JobID: job.ID, TriggerType: "schedule", FireKey: "rollback", Status: "queued"}
		if err := txRuns.Create(ctx, run); err != nil {
			return err
		}
		return rollbackErr
	})
	if !errors.Is(err, rollbackErr) {
		t.Fatalf("transaction error = %v", err)
	}
	if _, err := runs.FindByFireKey(ctx, job.ID, "rollback"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("rolled back record lookup = %v", err)
	}
	var created entity.ScheduledJobRun
	if err := runs.WithJobLock(ctx, job.ID, func(txRuns ScheduledJobRunRepository) error {
		created = entity.ScheduledJobRun{JobID: job.ID, TriggerType: "schedule", FireKey: "committed", Status: "queued"}
		return txRuns.Create(ctx, &created)
	}); err != nil {
		t.Fatal(err)
	}
	if run, err := runs.FindByFireKey(ctx, job.ID, "committed"); err != nil || run.ID != created.ID {
		t.Fatalf("committed record = %+v, %v", run, err)
	}
	for _, status := range []string{"queued", "running", "success", "failed", "timeout", "cancelled", "skipped"} {
		if err := runs.UpdateFields(ctx, created.ID, map[string]interface{}{"status": status}); err != nil {
			t.Fatal(err)
		}
		run, err := runs.FindRunning(ctx, job.ID)
		if status == "queued" || status == "running" {
			if err != nil || run.ID != created.ID {
				t.Fatalf("active record for %s = %+v, %v", status, run, err)
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("finished record %s returned as active: %+v, %v", status, run, err)
		}
	}
	if _, err := runs.FindByFireKey(ctx, job.ID+1, "committed"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("other job matched fire key: %v", err)
	}
	called := false
	err = runs.WithJobLock(ctx, job.ID+1, func(ScheduledJobRunRepository) error { called = true; return nil })
	if !errors.Is(err, gorm.ErrRecordNotFound) || called {
		t.Fatalf("missing job lock = %v, callback called = %v", err, called)
	}
}
