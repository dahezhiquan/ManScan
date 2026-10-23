package repository

import (
	"context"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
)

type ScheduledJobRunRepository interface {
	Create(ctx context.Context, item *entity.ScheduledJobRun) error
	FindByID(ctx context.Context, id int64) (*entity.ScheduledJobRun, error)
	ListByJob(ctx context.Context, jobID int64, query dto.ListScheduledJobRunsQuery) (*dto.PageResult[entity.ScheduledJobRun], error)
	HasRunning(ctx context.Context, jobID int64) (bool, error)
	UpdateFields(ctx context.Context, id int64, fields map[string]interface{}) error
}

type scheduledJobRunRepository struct{ db *gorm.DB }

// NewScheduledJobRunRepository 创建定时任务执行记录存储实现。
func NewScheduledJobRunRepository(db *gorm.DB) ScheduledJobRunRepository {
	return &scheduledJobRunRepository{db: db}
}

func (r *scheduledJobRunRepository) Create(ctx context.Context, item *entity.ScheduledJobRun) error {
	return r.db.WithContext(ctx).Create(item).Error
}

func (r *scheduledJobRunRepository) FindByID(ctx context.Context, id int64) (*entity.ScheduledJobRun, error) {
	var item entity.ScheduledJobRun
	if err := r.db.WithContext(ctx).First(&item, id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *scheduledJobRunRepository) ListByJob(ctx context.Context, jobID int64, query dto.ListScheduledJobRunsQuery) (*dto.PageResult[entity.ScheduledJobRun], error) {
	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	base := r.db.WithContext(ctx).Model(&entity.ScheduledJobRun{}).Where("job_id = ?", jobID)
	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, err
	}
	items := make([]entity.ScheduledJobRun, 0)
	if err := base.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&items).Error; err != nil {
		return nil, err
	}
	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	return &dto.PageResult[entity.ScheduledJobRun]{Page: page, PageSize: pageSize, Total: int(total), TotalPages: totalPages, Items: items}, nil
}

func (r *scheduledJobRunRepository) HasRunning(ctx context.Context, jobID int64) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&entity.ScheduledJobRun{}).Where("job_id = ? AND status IN ?", jobID, []string{"queued", "running"}).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *scheduledJobRunRepository) UpdateFields(ctx context.Context, id int64, fields map[string]interface{}) error {
	return r.db.WithContext(ctx).Model(&entity.ScheduledJobRun{}).Where("id = ?", id).Updates(fields).Error
}
