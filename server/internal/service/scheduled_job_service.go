package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"

	"gorm.io/gorm"
)

type ScheduledJobService interface {
	Create(ctx context.Context, request dto.CreateScheduledJobRequest) (*dto.ScheduledJobListItem, error)
	List(ctx context.Context, query dto.ListScheduledJobsQuery) (*dto.PageResult[dto.ScheduledJobListItem], error)
	Get(ctx context.Context, id int64) (*dto.ScheduledJobListItem, error)
	Update(ctx context.Context, id int64, request dto.UpdateScheduledJobRequest) (*dto.ScheduledJobListItem, error)
	Delete(ctx context.Context, id int64) error
	Trigger(ctx context.Context, id int64, triggerType string) (*dto.TriggerScheduledJobResponse, error)
	ListRuns(ctx context.Context, id int64, query dto.ListScheduledJobRunsQuery) (*dto.PageResult[dto.ScheduledJobRunItem], error)
	GetRun(ctx context.Context, id int64) (*dto.ScheduledJobRunItem, error)
}

var ErrInvalidScheduledJob = errors.New("定时任务参数不合法")

type scheduledJobService struct {
	jobs      repository.ScheduledJobRepository
	runs      repository.ScheduledJobRunRepository
	scheduler SchedulerManager
	registry  JobHandlerRegistry
}

// NewScheduledJobService 创建定时任务业务服务。
func NewScheduledJobService(jobs repository.ScheduledJobRepository, runs repository.ScheduledJobRunRepository, scheduler SchedulerManager, registry JobHandlerRegistry) ScheduledJobService {
	return &scheduledJobService{jobs: jobs, runs: runs, scheduler: scheduler, registry: registry}
}

func (s *scheduledJobService) Create(ctx context.Context, request dto.CreateScheduledJobRequest) (*dto.ScheduledJobListItem, error) {
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	item, err := buildScheduledJob(request.Name, request.Description, request.JobType, request.CronExpr, request.Timezone, enabled, request.APIKeyID, request.ConfigJSON, request.ConcurrencyPolicy, request.TimeoutSeconds, s.registry)
	if err != nil {
		return nil, err
	}
	if err := s.jobs.Create(ctx, item); err != nil {
		return nil, err
	}
	if err := s.scheduler.AddOrUpdate(ctx, item.ID); err != nil {
		return nil, err
	}
	result := toScheduledJobListItem(*item)
	return &result, nil
}

func (s *scheduledJobService) List(ctx context.Context, query dto.ListScheduledJobsQuery) (*dto.PageResult[dto.ScheduledJobListItem], error) {
	page, err := s.jobs.List(ctx, query)
	if err != nil {
		return nil, err
	}
	items := make([]dto.ScheduledJobListItem, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, toScheduledJobListItem(item))
	}
	return &dto.PageResult[dto.ScheduledJobListItem]{Page: page.Page, PageSize: page.PageSize, Total: page.Total, TotalPages: page.TotalPages, Items: items}, nil
}

func (s *scheduledJobService) Get(ctx context.Context, id int64) (*dto.ScheduledJobListItem, error) {
	item, err := s.jobs.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	result := toScheduledJobListItem(*item)
	return &result, nil
}

func (s *scheduledJobService) Update(ctx context.Context, id int64, request dto.UpdateScheduledJobRequest) (*dto.ScheduledJobListItem, error) {
	if id <= 0 {
		return nil, ErrInvalidScheduledJob
	}
	item, err := buildScheduledJob(request.Name, request.Description, request.JobType, request.CronExpr, request.Timezone, request.Enabled, request.APIKeyID, request.ConfigJSON, request.ConcurrencyPolicy, request.TimeoutSeconds, s.registry)
	if err != nil {
		return nil, err
	}
	item.ID = id
	if _, err := s.jobs.FindByID(ctx, id); err != nil {
		return nil, err
	}
	if err := s.jobs.Update(ctx, item); err != nil {
		return nil, err
	}
	if err := s.scheduler.AddOrUpdate(ctx, id); err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

func (s *scheduledJobService) Delete(ctx context.Context, id int64) error {
	if id <= 0 {
		return ErrInvalidScheduledJob
	}
	if _, err := s.jobs.FindByID(ctx, id); err != nil {
		return err
	}
	s.scheduler.Remove(id)
	deleted, err := s.jobs.Delete(ctx, id)
	if err != nil {
		return err
	}
	if deleted == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (s *scheduledJobService) Trigger(ctx context.Context, id int64, triggerType string) (*dto.TriggerScheduledJobResponse, error) {
	if id <= 0 || (triggerType != "manual" && triggerType != "schedule") {
		return nil, ErrInvalidScheduledJob
	}
	run, err := s.scheduler.Trigger(ctx, id, triggerType)
	if err != nil {
		return nil, err
	}
	result := toScheduledJobRunItem(*run)
	return &dto.TriggerScheduledJobResponse{Run: &result}, nil
}

func (s *scheduledJobService) ListRuns(ctx context.Context, id int64, query dto.ListScheduledJobRunsQuery) (*dto.PageResult[dto.ScheduledJobRunItem], error) {
	if _, err := s.jobs.FindByID(ctx, id); err != nil {
		return nil, err
	}
	page, err := s.runs.ListByJob(ctx, id, query)
	if err != nil {
		return nil, err
	}
	items := make([]dto.ScheduledJobRunItem, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, toScheduledJobRunItem(item))
	}
	return &dto.PageResult[dto.ScheduledJobRunItem]{Page: page.Page, PageSize: page.PageSize, Total: page.Total, TotalPages: page.TotalPages, Items: items}, nil
}

func (s *scheduledJobService) GetRun(ctx context.Context, id int64) (*dto.ScheduledJobRunItem, error) {
	item, err := s.runs.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	result := toScheduledJobRunItem(*item)
	return &result, nil
}

func buildScheduledJob(name, description, jobType, cronExpr, timezone string, enabled bool, apiKeyID *int64, config, concurrency string, timeout int, registry JobHandlerRegistry) (*entity.ScheduledJob, error) {
	name, jobType, cronExpr, timezone, concurrency = strings.TrimSpace(name), strings.TrimSpace(jobType), strings.TrimSpace(cronExpr), strings.TrimSpace(timezone), strings.TrimSpace(concurrency)
	if timezone == "" {
		timezone = "Asia/Shanghai"
	}
	if concurrency == "" {
		concurrency = "forbid"
	}
	if config == "" {
		config = "{}"
	}
	if name == "" || jobType == "" || len(config) > 1<<20 || !json.Valid([]byte(config)) {
		return nil, ErrInvalidScheduledJob
	}
	if err := validateScheduledJob(cronExpr, timezone, concurrency, timeout); err != nil {
		return nil, err
	}
	if registry != nil {
		if err := registry.Validate(jobType, json.RawMessage(config)); err != nil && !errors.Is(err, ErrScheduledJobHandlerNotFound) {
			return nil, err
		}
	}
	return &entity.ScheduledJob{Name: name, Description: strings.TrimSpace(description), JobType: jobType, CronExpr: cronExpr, Timezone: timezone, Enabled: enabled, APIKeyID: apiKeyID, ConfigJSON: config, ConcurrencyPolicy: concurrency, TimeoutSeconds: timeout}, nil
}

func toScheduledJobListItem(item entity.ScheduledJob) dto.ScheduledJobListItem {
	return dto.ScheduledJobListItem{ID: item.ID, Name: item.Name, Description: item.Description, JobType: item.JobType, CronExpr: item.CronExpr, Timezone: item.Timezone, Enabled: item.Enabled, APIKeyID: item.APIKeyID, ConfigJSON: item.ConfigJSON, ConcurrencyPolicy: item.ConcurrencyPolicy, TimeoutSeconds: item.TimeoutSeconds, NextRunAt: item.NextRunAt, LastRunAt: item.LastRunAt, LastStatus: item.LastStatus, LastError: item.LastError, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}
func toScheduledJobRunItem(item entity.ScheduledJobRun) dto.ScheduledJobRunItem {
	var percent *float64
	resultSummary := ""
	if item.ResultSummary != nil {
		resultSummary = *item.ResultSummary
	}
	if item.ProgressTotal > 0 {
		value := float64(item.ProgressCurrent) * 100 / float64(item.ProgressTotal)
		percent = &value
	}
	return dto.ScheduledJobRunItem{ID: item.ID, JobID: item.JobID, TriggerType: item.TriggerType, Status: item.Status, ProgressCurrent: item.ProgressCurrent, ProgressTotal: item.ProgressTotal, ProgressPercent: percent, ProgressPhase: item.ProgressPhase, ProgressMessage: item.ProgressMessage, ProgressUpdatedAt: item.ProgressUpdatedAt, StartedAt: item.StartedAt, FinishedAt: item.FinishedAt, RelatedType: item.RelatedType, RelatedID: item.RelatedID, ResultRef: item.ResultRef, ResultSummary: resultSummary, ErrorMessage: item.ErrorMessage, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}
