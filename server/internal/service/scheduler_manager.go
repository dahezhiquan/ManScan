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
	StopJob(ctx context.Context, jobID int64) int
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

	runMu      sync.Mutex
	runCancels map[int64]map[int64]context.CancelFunc
}

// NewSchedulerManager 创建调度器；具体业务由 JobHandlerRegistry 提供。
func NewSchedulerManager(jobs repository.ScheduledJobRepository, runs repository.ScheduledJobRunRepository, registry JobHandlerRegistry, logger *logx.Logger) SchedulerManager {
	return &schedulerManager{
		jobs: jobs, runs: runs, registry: registry, logger: logger,
		cron:       cron.New(cron.WithParser(cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor))),
		entries:    make(map[int64]cron.EntryID),
		runCancels: make(map[int64]map[int64]context.CancelFunc),
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
		return s.jobs.UpdateNextRunAt(ctx, jobID, nil)
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

// StopJob 取消指定定时任务当前尚未完成的执行；不会改变后续调度开关。
func (s *schedulerManager) StopJob(_ context.Context, jobID int64) int {
	s.runMu.Lock()
	cancels := s.runCancels[jobID]
	count := len(cancels)
	for _, cancel := range cancels {
		cancel()
	}
	s.runMu.Unlock()
	return count
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
	s.mu.Lock()
	defer s.mu.Unlock()
	entryID, err := s.cron.AddFunc(schedule, func() {
		if err := s.refreshNextRunAt(job.ID); err != nil && s.logger != nil {
			s.logger.Error("update scheduled job next run failed", "job_id", job.ID, "error", err)
		}
		_, triggerErr := s.Trigger(context.Background(), job.ID, "schedule")
		if triggerErr != nil && s.logger != nil {
			s.logger.Error("scheduled job trigger failed", "job_id", job.ID, "error", triggerErr)
		}
	})
	if err != nil {
		return err
	}
	s.entries[job.ID] = entryID
	return s.updateNextRunAt(context.Background(), job.ID, entryID)
}

func (s *schedulerManager) refreshNextRunAt(jobID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entryID, registered := s.entries[jobID]
	if !registered {
		return nil
	}
	// 与注册、移除串行写入，避免旧回调覆盖新计划或禁用后的时间。
	return s.updateNextRunAt(context.Background(), jobID, entryID)
}

// updateNextRunAt 在持有 s.mu 时调用，使计划与数据库时间保持一致。
func (s *schedulerManager) updateNextRunAt(ctx context.Context, jobID int64, entryID cron.EntryID) error {
	entry := s.cron.Entry(entryID)
	now := time.Now()
	if entry.Schedule != nil && (entry.Next.IsZero() || !entry.Next.After(now)) {
		// Cron 启动前或回调并发执行时 Entry.Next 可能为空/已到期，按同一份计划计算下一次时间。
		entry.Next = entry.Schedule.Next(time.Now())
	}
	var nextRunAt *time.Time
	if !entry.Next.IsZero() {
		nextRunAt = &entry.Next
	}
	return s.jobs.UpdateNextRunAt(ctx, jobID, nextRunAt)
}

func (s *schedulerManager) Trigger(ctx context.Context, jobID int64, triggerType string) (*entity.ScheduledJobRun, error) {
	// 创建执行记录与登记取消函数必须原子完成，停止请求才能覆盖刚排队的执行。
	s.runMu.Lock()
	defer s.runMu.Unlock()
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
	runCtx, cancel := context.WithCancel(context.Background())
	s.registerRun(jobID, run.ID, cancel)
	go func() {
		defer cancel()
		s.execute(runCtx, *job, *run)
	}()
	return run, nil
}

func (s *schedulerManager) registerRun(jobID, runID int64, cancel context.CancelFunc) {
	if s.runCancels[jobID] == nil {
		s.runCancels[jobID] = make(map[int64]context.CancelFunc)
	}
	s.runCancels[jobID][runID] = cancel
}

func (s *schedulerManager) unregisterRun(jobID, runID int64) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if runs := s.runCancels[jobID]; runs != nil {
		delete(runs, runID)
		if len(runs) == 0 {
			delete(s.runCancels, jobID)
		}
	}
}

func (s *schedulerManager) execute(parent context.Context, job entity.ScheduledJob, run entity.ScheduledJobRun) {
	defer s.unregisterRun(job.ID, run.ID)
	started := time.Now()
	_ = s.runs.UpdateFields(context.Background(), run.ID, map[string]interface{}{"status": ScheduledJobStatusRunning, "started_at": started})
	ctx := parent
	if job.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, time.Duration(job.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	progress := &scheduledJobProgress{runs: s.runs, runID: run.ID}
	var err error
	if ctx.Err() != nil {
		err = ctx.Err()
	} else if s.registry == nil {
		err = ErrScheduledJobHandlerNotFound
	} else {
		handler, handlerErr := s.registry.Get(job.JobType)
		err = handlerErr
		if err == nil {
			err = handler.Execute(ctx, job, run, progress)
		}
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	status := ScheduledJobStatusSuccess
	fields := map[string]interface{}{"finished_at": time.Now(), "updated_at": time.Now()}
	if err != nil {
		status = ScheduledJobStatusFailed
		if errors.Is(ctx.Err(), context.Canceled) {
			status = ScheduledJobStatusCancel
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status = ScheduledJobStatusTimeout
		}
		fields["error_message"] = err.Error()
	}
	fields["status"] = status
	if updateErr := s.runs.UpdateFields(context.Background(), run.ID, fields); updateErr != nil && s.logger != nil {
		s.logger.Error("update scheduled job result failed", "job_id", job.ID, "run_id", run.ID, "error", updateErr)
	}
	now := time.Now()
	if updateErr := s.jobs.UpdateRuntime(context.Background(), job.ID, nil, &now, status, errorString(err)); updateErr != nil && s.logger != nil {
		s.logger.Error("update scheduled job runtime failed", "job_id", job.ID, "run_id", run.ID, "error", updateErr)
	}
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
	if timeout < 0 || timeout > 30*24*60*60 {
		return errors.New("超时时间必须在 0-2592000 秒之间（最多 30 天）")
	}
	return nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
