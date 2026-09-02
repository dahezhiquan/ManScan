package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestScanTaskRepositoryDeleteRemovesTaskAndResult(t *testing.T) {
	t.Parallel()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}

	if err := db.AutoMigrate(&entity.ScanTask{}, &entity.ScanTaskResult{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	startedAt := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Minute)
	if err := db.Create(&entity.ScanTask{
		ID:        1,
		TaskNo:    "task-1",
		Name:      "delete-task",
		Status:    "success",
		CreatedBy: "tester",
	}).Error; err != nil {
		t.Fatalf("Create task error = %v", err)
	}
	if err := db.Create(&entity.ScanTaskResult{
		TaskID:        1,
		TaskName:      "delete-task",
		CriticalCount: 1,
		CreatedAt:     &startedAt,
		FinishedAt:    &finishedAt,
	}).Error; err != nil {
		t.Fatalf("Create result error = %v", err)
	}

	repo := NewScanTaskRepository(db)
	deletedCount, err := repo.Delete(context.Background(), []int64{1})
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if deletedCount != 1 {
		t.Fatalf("deletedCount = %d, want 1", deletedCount)
	}

	var task entity.ScanTask
	if err := db.First(&task, 1).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("task still exists or unexpected error: %v", err)
	}

	var result entity.ScanTaskResult
	if err := db.Where("task_id = ?", 1).First(&result).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("result still exists or unexpected error: %v", err)
	}
}
