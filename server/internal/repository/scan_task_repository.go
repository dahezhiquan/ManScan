package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ScanTaskRepository interface {
	Create(ctx context.Context, task *entity.ScanTask) error
	FindByID(ctx context.Context, taskID int64) (*entity.ScanTask, error)
	List(ctx context.Context, query dto.ListScanTasksQuery) (*dto.PageResult[dto.ScanTaskListItem], error)
	ListAll(ctx context.Context, query dto.ListScanTasksQuery) ([]dto.ScanTaskListItem, error)
	Stats(ctx context.Context) (*dto.ScanTaskStats, error)
	FindResultByTaskID(ctx context.Context, taskID int64) (*entity.ScanTaskResult, error)
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

func (r *scanTaskRepository) List(ctx context.Context, query dto.ListScanTasksQuery) (*dto.PageResult[dto.ScanTaskListItem], error) {
	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}

	countQuery := r.applyListFilters(r.db.WithContext(ctx).Table("manscan_scan_tasks AS t"), query)
	var total int64
	if err := countQuery.Count(&total).Error; err != nil {
		return nil, err
	}

	items, err := r.listItems(ctx, query, (page-1)*pageSize, pageSize)
	if err != nil {
		return nil, err
	}

	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}

	return &dto.PageResult[dto.ScanTaskListItem]{
		Page:       page,
		PageSize:   pageSize,
		Total:      int(total),
		TotalPages: totalPages,
		Items:      items,
	}, nil
}

func (r *scanTaskRepository) ListAll(ctx context.Context, query dto.ListScanTasksQuery) ([]dto.ScanTaskListItem, error) {
	return r.listItems(ctx, query, 0, 0)
}

func (r *scanTaskRepository) Stats(ctx context.Context) (*dto.ScanTaskStats, error) {
	var stats dto.ScanTaskStats
	err := r.db.WithContext(ctx).Table("manscan_scan_tasks AS t").
		Select(`
			COUNT(*) AS total,
			SUM(CASE WHEN t.status = 'running' THEN 1 ELSE 0 END) AS running,
			COALESCE(SUM(CASE
				WHEN COALESCE(r.total_requests, 0) > COALESCE(r.real_requests, 0)
					THEN COALESCE(r.total_requests, 0) - COALESCE(r.real_requests, 0)
				ELSE 0
			END), 0) AS saved_requests
		`).
		Joins("LEFT JOIN manscan_task_results AS r ON r.task_id = t.id").
		Scan(&stats).Error
	if err != nil {
		return nil, err
	}
	return &stats, nil
}

func (r *scanTaskRepository) FindResultByTaskID(ctx context.Context, taskID int64) (*entity.ScanTaskResult, error) {
	var result entity.ScanTaskResult
	if err := r.db.WithContext(ctx).Where("task_id = ?", taskID).First(&result).Error; err != nil {
		return nil, err
	}
	return &result, nil
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
			"tech_count",
			"plugin_count",
			"target_count",
			"total_requests",
			"real_requests",
			"finished_at",
		}),
	}).Create(result).Error
}

func (r *scanTaskRepository) applyListFilters(db *gorm.DB, query dto.ListScanTasksQuery) *gorm.DB {
	if keyword := strings.TrimSpace(query.Keyword); keyword != "" {
		like := "%" + keyword + "%"
		db = db.Where(
			"(t.name LIKE ? OR t.task_no LIKE ? OR t.created_by LIKE ? OR t.description LIKE ?)",
			like,
			like,
			like,
			like,
		)
	}
	if len(query.Statuses) > 0 {
		db = db.Where("t.status IN ?", query.Statuses)
	}
	if len(query.ScanStrategies) > 0 {
		db = db.Where("t.scan_strategy IN ?", query.ScanStrategies)
	}
	if createdBy := strings.TrimSpace(query.CreatedBy); createdBy != "" {
		db = db.Where("t.created_by = ?", createdBy)
	}
	return db
}

func (r *scanTaskRepository) listItems(ctx context.Context, query dto.ListScanTasksQuery, offset, limit int) ([]dto.ScanTaskListItem, error) {
	items := make([]dto.ScanTaskListItem, 0)
	dataQuery := r.applyListFilters(r.db.WithContext(ctx).Table("manscan_scan_tasks AS t"), query).
		Select(`
			t.id,
			t.task_no,
			t.name,
			COALESCE(t.description, '') AS description,
			t.status,
			t.created_by,
			COALESCE(t.scan_strategy, 'auto') AS scan_strategy,
			t.started_at,
			t.finished_at,
			COALESCE(r.critical_count, 0) AS critical_count,
			COALESCE(r.high_count, 0) AS high_count,
			COALESCE(r.medium_count, 0) AS medium_count,
			COALESCE(r.low_count, 0) AS low_count,
			COALESCE(r.info_count, 0) AS info_count,
			COALESCE(r.tech_count, 0) AS tech_count,
			COALESCE(r.plugin_count, 0) AS plugin_count,
			COALESCE(r.target_count, 0) AS target_count,
			COALESCE(r.total_requests, 0) AS total_requests,
			COALESCE(r.real_requests, 0) AS real_requests
		`).
		Joins("LEFT JOIN manscan_task_results AS r ON r.task_id = t.id").
		Order("t.id DESC")
	if limit > 0 {
		dataQuery = dataQuery.Offset(offset).Limit(limit)
	}
	if err := dataQuery.Scan(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}
