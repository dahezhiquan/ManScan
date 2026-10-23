package repository

import (
	"context"
	"strings"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
)

type ScheduledJobRepository interface {
	Create(ctx context.Context, item *entity.ScheduledJob) error
	FindByID(ctx context.Context, id int64) (*entity.ScheduledJob, error)
	List(ctx context.Context, query dto.ListScheduledJobsQuery) (*dto.PageResult[entity.ScheduledJob], error)
	ListEnabled(ctx context.Context) ([]entity.ScheduledJob, error)
	Update(ctx context.Context, item *entity.ScheduledJob) error
	UpdateRuntime(ctx context.Context, id int64, nextRunAt, lastRunAt *time.Time, lastStatus, lastError string) error
	Delete(ctx context.Context, id int64) (int64, error)
}

type scheduledJobRepository struct{ db *gorm.DB }

// NewScheduledJobRepository 创建定时任务存储实现。
func NewScheduledJobRepository(db *gorm.DB) ScheduledJobRepository {
	return &scheduledJobRepository{db: db}
}

func (r *scheduledJobRepository) Create(ctx context.Context, item *entity.ScheduledJob) error {
	return r.db.WithContext(ctx).Create(item).Error
}

func (r *scheduledJobRepository) FindByID(ctx context.Context, id int64) (*entity.ScheduledJob, error) {
	var item entity.ScheduledJob
	if err := r.db.WithContext(ctx).First(&item, id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *scheduledJobRepository) List(ctx context.Context, query dto.ListScheduledJobsQuery) (*dto.PageResult[entity.ScheduledJob], error) {
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
	base := r.db.WithContext(ctx).Model(&entity.ScheduledJob{})
	if keyword := strings.TrimSpace(query.Keyword); keyword != "" {
		like := "%" + keyword + "%"
		base = base.Where("name LIKE ? OR description LIKE ? OR job_type LIKE ?", like, like, like)
	}
	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, err
	}
	items := make([]entity.ScheduledJob, 0)
	if err := base.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&items).Error; err != nil {
		return nil, err
	}
	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	return &dto.PageResult[entity.ScheduledJob]{Page: page, PageSize: pageSize, Total: int(total), TotalPages: totalPages, Items: items}, nil
}

func (r *scheduledJobRepository) ListEnabled(ctx context.Context) ([]entity.ScheduledJob, error) {
	items := make([]entity.ScheduledJob, 0)
	if err := r.db.WithContext(ctx).Where("enabled = ?", true).Order("id ASC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (r *scheduledJobRepository) Update(ctx context.Context, item *entity.ScheduledJob) error {
	return r.db.WithContext(ctx).Model(&entity.ScheduledJob{}).Where("id = ?", item.ID).Updates(map[string]interface{}{
		"name": item.Name, "description": item.Description, "job_type": item.JobType,
		"cron_expr": item.CronExpr, "timezone": item.Timezone, "enabled": item.Enabled,
		"api_key_id": item.APIKeyID, "config_json": item.ConfigJSON,
		"concurrency_policy": item.ConcurrencyPolicy, "timeout_seconds": item.TimeoutSeconds,
	}).Error
}

func (r *scheduledJobRepository) UpdateRuntime(ctx context.Context, id int64, nextRunAt, lastRunAt *time.Time, lastStatus, lastError string) error {
	updates := make(map[string]interface{})
	if nextRunAt != nil {
		updates["next_run_at"] = nextRunAt
	}
	if lastRunAt != nil {
		updates["last_run_at"] = lastRunAt
	}
	if lastStatus != "" {
		updates["last_status"] = lastStatus
	}
	if lastError != "" || lastStatus != "" {
		updates["last_error"] = lastError
	}
	if len(updates) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Model(&entity.ScheduledJob{}).Where("id = ?", id).Updates(updates).Error
}

func (r *scheduledJobRepository) Delete(ctx context.Context, id int64) (int64, error) {
	result := r.db.WithContext(ctx).Delete(&entity.ScheduledJob{}, id)
	return result.RowsAffected, result.Error
}
