package repository

import (
	"context"
	"errors"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ScanTaskRepository interface {
	Create(ctx context.Context, task *entity.ScanTask) error
	FindByID(ctx context.Context, taskID int64) (*entity.ScanTask, error)
	UpdateStatus(ctx context.Context, taskID int64, status string, startedAt, finishedAt *time.Time) error
	UpsertResult(ctx context.Context, result *entity.ScanTaskResult) error
}

type scanTaskRepository struct {
	db *gorm.DB
}

func NewScanTaskRepository(db *gorm.DB) ScanTaskRepository {
	return &scanTaskRepository{db: db}
}

func (r *scanTaskRepository) Create(ctx context.Context, task *entity.ScanTask) error {
	if task == nil {
		return errors.New("scan task is nil")
	}
	return r.db.WithContext(ctx).Create(task).Error
}

func (r *scanTaskRepository) FindByID(ctx context.Context, taskID int64) (*entity.ScanTask, error) {
	var task entity.ScanTask
	if err := r.db.WithContext(ctx).First(&task, taskID).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (r *scanTaskRepository) UpdateStatus(ctx context.Context, taskID int64, status string, startedAt, finishedAt *time.Time) error {
	updates := map[string]interface{}{
		"status": status,
	}
	if startedAt != nil {
		updates["started_at"] = *startedAt
	}
	if finishedAt != nil {
		updates["finished_at"] = *finishedAt
	}
	return r.db.WithContext(ctx).Model(&entity.ScanTask{}).Where("id = ?", taskID).Updates(updates).Error
}

func (r *scanTaskRepository) UpsertResult(ctx context.Context, result *entity.ScanTaskResult) error {
	if result == nil {
		return errors.New("scan task result is nil")
	}
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "task_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"task_name",
			"critical_count",
			"high_count",
			"medium_count",
			"low_count",
			"info_count",
			"plugin_count",
			"target_count",
			"finished_at",
		}),
	}).Create(result).Error
}
