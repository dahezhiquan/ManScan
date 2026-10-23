package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/repository"

	"github.com/robfig/cron/v3"
	"github.com/rs/xid"
)

const (
	ScheduledJobStatusQueued  = "queued"
	ScheduledJobStatusRunning = "running"
	ScheduledJobStatusSuccess = "success"
	ScheduledJobStatusFailed  = "failed"
	ScheduledJobStatusSkipped = "skipped"
	ScheduledJobStatusTimeout = "timeout"
	ScheduledJobStatusCancel  = "cancelled"
)

// SchedulerManager 管理数据库任务在进程内的 Cron 注册和执行。
type SchedulerManager interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	AddOrUpdate(ctx context.Context, jobID int64) error
	Remove(jobID int64)
	Trigger(ctx context.Context, jobID int64, triggerType string) (*entity.ScheduledJobRun, error)
}

type schedulerManager struct {
	jobs     repository.ScheduledJobRepository
	runs     repository.ScheduledJobRunRepository
	registry JobHandlerRegistry
	logger   *logx.Logger
	cron     *cron.Cron

	mu      sync.Mutex
	entries map[int64]cron.EntryID
	started bool
}

// NewSchedulerManager 创建调度器；具体业务由 JobHandlerRegistry 提供。
func NewSchedulerManager(jobs repository.ScheduledJobRepository, runs repository.ScheduledJobRunRepository, registry JobHandlerRegistry, logger *logx.Logger) SchedulerManager {
	return &schedulerManager{
		jobs: jobs, runs: runs, registry: registry, logger: logger,
		cron:    cron.New(cron.WithParser(cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor))),
		entries: make(map[int64]cron.EntryID),
	}
}

func (s *schedulerManager) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	items, err := s.jobs.ListEnabled(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	for _, job := range items {
		if err := s.addJob(job); err != nil && s.logger != nil {
			s.logger.Error("register scheduled job failed", "job_id", job.ID, "error", err)
		}
	}
	s.cron.Start()
	return nil
}

func (s *schedulerManager) Stop(ctx context.Context) error {
	_ = ctx
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = false
	s.mu.Unlock()
	stopCtx := s.cron.Stop()
	select {
	case <-stopCtx.Done():
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("等待定时任务停止超时")
	}
}

func (s *schedulerManager) AddOrUpdate(ctx context.Context, jobID int64) error {
	job, err := s.jobs.FindByID(ctx, jobID)
	if err != nil {
		return err
	}
	s.Remove(jobID)
	if !job.Enabled {
		return nil
	}
	return s.addJob(*job)
}

func (s *schedulerManager) Remove(jobID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entryID, ok := s.entries[jobID]; ok {
		s.cron.Remove(entryID)
		delete(s.entries, jobID)
	}
}

func (s *schedulerManager) addJob(job entity.ScheduledJob) error {
	if err := validateScheduledJob(job.CronExpr, job.Timezone, job.ConcurrencyPolicy, job.TimeoutSeconds); err != nil {
		return err
	}
	if s.registry != nil {
		if err := s.registry.Validate(job.JobType, json.RawMessage(job.ConfigJSON)); err != nil && !errors.Is(err, ErrScheduledJobHandlerNotFound) {
			return err
		}
	}
	schedule := strings.TrimSpace(job.CronExpr)
	if strings.TrimSpace(job.Timezone) != "" {
		schedule = "CRON_TZ=" + strings.TrimSpace(job.Timezone) + " " + schedule
	}
	entryID, err := s.cron.AddFunc(schedule, func() {
		_, triggerErr := s.Trigger(context.Background(), job.ID, "schedule")
		if triggerErr != nil && s.logger != nil {
			s.logger.Error("scheduled job trigger failed", "job_id", job.ID, "error", triggerErr)
		}
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.entries[job.ID] = entryID
	s.mu.Unlock()
	entry := s.cron.Entry(entryID)
	if !entry.Next.IsZero() {
		_ = s.jobs.UpdateRuntime(context.Background(), job.ID, &entry.Next, nil, "", "")
	}
	return nil
}

func (s *schedulerManager) Trigger(ctx context.Context, jobID int64, triggerType string) (*entity.ScheduledJobRun, error) {
	job, err := s.jobs.FindByID(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if triggerType == "schedule" && !job.Enabled {
		return nil, errors.New("定时任务未启用")
	}
	if job.ConcurrencyPolicy == "" {
		job.ConcurrencyPolicy = "forbid"
	}
	if job.ConcurrencyPolicy == "forbid" {
		running, checkErr := s.runs.HasRunning(ctx, jobID)
		if checkErr != nil {
			return nil, checkErr
		}
		if running {
			now := time.Now()
			run := &entity.ScheduledJobRun{JobID: jobID, TriggerType: triggerType, FireKey: xid.New().String(), Status: ScheduledJobStatusSkipped, ProgressUpdatedAt: &now, ErrorMessage: "已有执行中的任务"}
			if err := s.runs.Create(ctx, run); err != nil {
				return nil, err
			}
			return run, nil
		}
	}
	run := &entity.ScheduledJobRun{JobID: jobID, TriggerType: triggerType, FireKey: xid.New().String(), Status: ScheduledJobStatusQueued}
	if err := s.runs.Create(ctx, run); err != nil {
		return nil, err
	}
	go s.execute(*job, *run)
	return run, nil
}

func (s *schedulerManager) execute(job entity.ScheduledJob, run entity.ScheduledJobRun) {
	started := time.Now()
	_ = s.runs.UpdateFields(context.Background(), run.ID, map[string]interface{}{"status": ScheduledJobStatusRunning, "started_at": started})
	ctx := context.Background()
	if job.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(job.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	progress := &scheduledJobProgress{runs: s.runs, runID: run.ID}
	var err error
	if s.registry == nil {
		err = ErrScheduledJobHandlerNotFound
	} else {
		handler, handlerErr := s.registry.Get(job.JobType)
		err = handlerErr
		if err == nil {
			err = handler.Execute(ctx, job, run, progress)
		}
	}
	status := ScheduledJobStatusSuccess
	fields := map[string]interface{}{"finished_at": time.Now(), "updated_at": time.Now()}
	if err != nil {
		status = ScheduledJobStatusFailed
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status = ScheduledJobStatusTimeout
		}
		fields["error_message"] = err.Error()
	}
	fields["status"] = status
	_ = s.runs.UpdateFields(context.Background(), run.ID, fields)
	now := time.Now()
	_ = s.jobs.UpdateRuntime(context.Background(), job.ID, nil, &now, status, errorString(err))
	if s.logger != nil && err != nil {
		s.logger.Error("scheduled job execution failed", "job_id", job.ID, "run_id", run.ID, "error", err)
	}
}

type scheduledJobProgress struct {
	runs  repository.ScheduledJobRunRepository
	runID int64
}

func (p *scheduledJobProgress) Report(ctx context.Context, current, total int64, phase, message string) error {
	now := time.Now()
	return p.runs.UpdateFields(ctx, p.runID, map[string]interface{}{"progress_current": current, "progress_total": total, "progress_phase": phase, "progress_message": message, "progress_updated_at": now})
}

func validateScheduledJob(cronExpr, timezone, concurrency string, timeout int) error {
	if _, err := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor).Parse(strings.TrimSpace(cronExpr)); err != nil {
		return fmt.Errorf("Cron 表达式不合法: %w", err)
	}
	if strings.TrimSpace(timezone) == "" {
		timezone = "Asia/Shanghai"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return fmt.Errorf("时区不合法: %w", err)
	}
	if concurrency != "" && concurrency != "forbid" && concurrency != "allow" {
		return errors.New("并发策略只能是 forbid 或 allow")
	}
	if timeout < 0 || timeout > 86400 {
		return errors.New("超时时间必须在 0-86400 秒之间")
	}
	return nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
