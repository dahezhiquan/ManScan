package repository

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestScheduledJobRepositoryUpdateNextRunAt(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "scheduled_jobs.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&entity.ScheduledJob{}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	repo := NewScheduledJobRepository(db)
	job := entity.ScheduledJob{Name: "test", JobType: "test.sync", CronExpr: "0 0 * * *", ConfigJSON: "{}", LastStatus: "success"}
	if err := repo.Create(ctx, &job); err != nil {
		t.Fatal(err)
	}
	other := job
	other.ID = 0
	if err := repo.Create(ctx, &other); err != nil {
		t.Fatal(err)
	}
	next := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := repo.UpdateNextRunAt(ctx, job.ID, &next); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.FindByID(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.NextRunAt == nil || !stored.NextRunAt.Equal(next) {
		t.Fatalf("next run = %v, want %v", stored.NextRunAt, next)
	}
	if err := repo.UpdateNextRunAt(ctx, job.ID, nil); err != nil {
		t.Fatal(err)
	}
	stored, err = repo.FindByID(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.NextRunAt != nil || stored.LastStatus != "success" {
		t.Fatalf("clearing next run changed runtime fields: %+v", stored)
	}
	untouched, err := repo.FindByID(ctx, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	if untouched.NextRunAt != nil {
		t.Fatalf("updated another job's next run: %v", untouched.NextRunAt)
	}
}
