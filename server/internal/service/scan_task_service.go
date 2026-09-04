package service

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/pkg/scanruntime"
	"ManScan/server/internal/pkg/templateprotocol"
	"ManScan/server/internal/repository"

	"github.com/rs/xid"
	"gorm.io/gorm"
)

type ScanTaskService interface {
	Create(ctx context.Context, request dto.CreateScanTaskRequest) (*dto.ScanTaskSummary, error)
	Rescan(ctx context.Context, taskID int64) (*dto.ScanTaskSummary, error)
	Delete(ctx context.Context, request dto.DeleteScanTaskRequest) (*dto.DeleteScanTaskResponse, error)
	Pause(ctx context.Context, taskID int64) (*dto.PauseScanTaskResponse, error)
	Resume(ctx context.Context, taskID int64) (*dto.ResumeScanTaskResponse, error)
	Cancel(ctx context.Context, taskID int64) (*dto.CancelScanTaskResponse, error)
	List(ctx context.Context, query dto.ListScanTasksQuery) (*dto.PageResult[dto.ScanTaskListItem], error)
	ListNameOptions(ctx context.Context, query dto.ListScanTaskNameOptionsQuery) (*dto.PageResult[dto.ScanTaskNameOption], error)
	Stats(ctx context.Context) (*dto.ScanTaskStats, error)
	Get(ctx context.Context, taskID int64) (*dto.GetScanTaskResponse, error)
	GetLogs(ctx context.Context, taskID, offset int64, limit int, direction string) (*dto.ScanTaskLogsResponse, error)
	GetResponseArchive(ctx context.Context, taskID int64) (*dto.ScanTaskResponseArchive, error)
	Subscribe(ctx context.Context, taskID, offset int64) (*dto.ScanTaskSummary, scanruntime.TaskProgressSnapshot, []scanruntime.TaskLogEvent, int64, chan scanruntime.TaskLogEvent, func() dto.ScanTaskSummary, func() scanruntime.TaskProgressSnapshot, func(), error)
}

var ErrScanTaskNotPausable = errors.New("当前任务状态不支持暂停")
var ErrScanTaskNotCancelable = errors.New("当前任务状态不支持取消")
var ErrScanTaskNotResumable = errors.New("当前任务状态不支持恢复")
var ErrScanTaskNotDeletable = errors.New("当前任务状态不支持删除")
var ErrScanTaskInvalidConfiguration = errors.New("原任务配置不完整，无法重新扫描")
var ErrInvalidScanTaskIDs = errors.New("扫描任务 id 列表不合法")
var ErrScanTaskResponseArchiveNotFound = errors.New("请求/响应压缩包不存在")

const maxBatchScanTaskIDs = 1000

const (
	logDirectionForward = "forward"
	logDirectionBefore  = "before"
)

type scanTaskService struct {
	repository              repository.ScanTaskRepository
	vulnerabilityRepository repository.VulnerabilityRepository
	templateRepository      repository.TemplateRepository
	logger                  *logx.Logger
	rootDir                 string
	runtimeDir              string

	mu         sync.RWMutex
	states     map[int64]*scanTaskRuntime
	taskRunner func(taskID int64, plan *normalizedTaskRequest, runtime *scanTaskRuntime)
}

type normalizedTaskRequest struct {
	Raw              dto.CreateScanTaskRequest
	Name             string
	Description      string
	CreatedBy        string
	CollectedTargets []string
}

type scanTaskRuntime struct {
	state              *scanruntime.State
	vulnerabilityQueue *vulnerabilityQueue

	mu              sync.Mutex
	cancel          context.CancelFunc
	interrupt       func()
	terminate       func()
	cancelRequested bool
	pauseRequested  bool
	finalized       bool
}

func NewScanTaskService(
	repo repository.ScanTaskRepository,
	vulnerabilityRepo repository.VulnerabilityRepository,
	templateRepo repository.TemplateRepository,
	logger *logx.Logger,
	rootDir string,
) ScanTaskService {
	runtimeDir := filepath.Join(rootDir, "data", "runtime")
	_ = os.MkdirAll(runtimeDir, 0o755)

	return &scanTaskService{
		repository:              repo,
		vulnerabilityRepository: vulnerabilityRepo,
		templateRepository:      templateRepo,
		logger:                  logger,
		rootDir:                 rootDir,
		runtimeDir:              runtimeDir,
		states:                  make(map[int64]*scanTaskRuntime),
	}
}

func (s *scanTaskService) Create(ctx context.Context, request dto.CreateScanTaskRequest) (*dto.ScanTaskSummary, error) {
	plan, err := normalizeCreateTaskRequest(request)
	if err != nil {
		return nil, err
	}

	return s.createFromNormalizedPlan(ctx, plan)
}

func (s *scanTaskService) Rescan(ctx context.Context, taskID int64) (*dto.ScanTaskSummary, error) {
	task, err := s.repository.FindByID(ctx, taskID)
	if err != nil {
		return nil, err
	}

	plan, err := normalizedTaskRequestFromTask(task)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrScanTaskInvalidConfiguration, err)
	}

	return s.createFromNormalizedPlan(ctx, plan)
}

func (s *scanTaskService) Delete(ctx context.Context, request dto.DeleteScanTaskRequest) (*dto.DeleteScanTaskResponse, error) {
	rawIDs := make([]int64, 0, len(request.IDs)+1)
	if request.ID != nil {
		rawIDs = append(rawIDs, *request.ID)
	}
	rawIDs = append(rawIDs, request.IDs...)

	ids, err := normalizeScanTaskIDs(rawIDs)
	if err != nil {
		return nil, err
	}

	tasks, err := s.repository.FindByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, task := range tasks {
		if !isDeletableScanTaskStatus(task.Status) {
			return nil, ErrScanTaskNotDeletable
		}
	}

	deletedCount, err := s.repository.Delete(ctx, ids)
	if err != nil {
		return nil, err
	}

	s.cleanupDeletedTaskArtifacts(ids)

	return &dto.DeleteScanTaskResponse{
		IDs:          ids,
		DeletedCount: deletedCount,
	}, nil
}

func (s *scanTaskService) createFromNormalizedPlan(ctx context.Context, plan *normalizedTaskRequest) (*dto.ScanTaskSummary, error) {
	if plan == nil {
		return nil, errors.New("扫描任务配置为空")
	}

	request := plan.Raw
	taskNo := xid.New().String()
	task := &entity.ScanTask{
		TaskNo:                        taskNo,
		Name:                          plan.Name,
		Description:                   nullableString(plan.Description),
		Status:                        "pending",
		CreatedBy:                     plan.CreatedBy,
		Targets:                       mustJSON(plan.CollectedTargets),
		InlineTargetsList:             nullableString(request.InlineTargetsList),
		ExcludeTargets:                mustJSON(cleanStringSlice(request.ExcludeTargets)),
		ScanAllIPs:                    request.ScanAllIPs,
		IPVersion:                     mustJSON(cleanStringSlice(request.IPVersion)),
		InputFileMode:                 firstNonEmpty(strings.TrimSpace(request.InputFileMode), "list"),
		NewTemplates:                  request.NewTemplates,
		AutomaticScan:                 request.AutomaticScan,
		EnableGlobalMatchersTemplates: request.EnableGlobalMatchersTemplates,
		Tags:                          mustJSON(cleanStringSlice(request.Tags)),
		IncludeIDs:                    mustJSON(cleanStringSlice(request.IncludeIDs)),
		Severities:                    mustJSON(cleanStringSlice(request.Severities)),
		Protocols:                     mustJSON(templateprotocol.NormalizeList(request.Protocols)),
		StoreResponse:                 request.StoreResponse,
		Timestamp:                     request.Timestamp,
		MatcherStatus:                 request.MatcherStatus,
		CustomHeaders:                 mustJSON(cleanStringSlice(request.CustomHeaders)),
		Vars:                          mustJSON(cleanStringSlice(request.Vars)),
		FollowRedirects:               request.FollowRedirects,
		FollowHostRedirects:           request.FollowHostRedirects,
		MaxRedirects:                  defaultInt(request.MaxRedirects, 10),
		DisableRedirects:              request.DisableRedirects,
		OfflineHTTP:                   request.OfflineHTTP,
		ForceAttemptHTTP2:             request.ForceAttemptHTTP2,
		SNI:                           nullableString(request.SNI),
		AllowLocalFileAccess:          request.AllowLocalFileAccess,
		AttackType:                    nullableString(request.AttackType),
		SourceIP:                      nullableString(request.SourceIP),
		ResponseReadSize:              request.ResponseReadSize,
		ResponseSaveSize:              defaultInt(request.ResponseSaveSize, 1048576),
		TLSImpersonate:                request.TLSImpersonate,
		RateLimit:                     defaultInt(request.RateLimit, 150),
		RateLimitDuration:             defaultInt64(request.RateLimitDuration, 1000),
		BulkSize:                      defaultInt(request.BulkSize, 25),
		TemplateThreads:               defaultInt(request.TemplateThreads, 25),
		HeadlessBulkSize:              defaultInt(request.HeadlessBulkSize, 10),
		HeadlessTemplateThreads:       defaultInt(request.HeadlessTemplateThreads, 10),
		JSConcurrency:                 defaultInt(request.JSConcurrency, 120),
		PayloadConcurrency:            defaultInt(request.PayloadConcurrency, 25),
		ProbeConcurrency:              defaultInt(request.ProbeConcurrency, 50),
		Timeout:                       defaultInt(request.Timeout, 10),
		Retries:                       defaultInt(request.Retries, 1),
		MaxHostError:                  defaultInt(request.MaxHostError, 30),
		NoHostErrors:                  request.NoHostErrors,
		Project:                       request.Project,
		ProjectPath:                   nullableString(request.ProjectPath),
		ScanStrategy:                  nullableString(firstNonEmpty(request.ScanStrategy, "auto")),
		DisableHTTPProbe:              request.DisableHTTPProbe,
		Headless:                      request.Headless,
		PageTimeout:                   defaultInt(request.PageTimeout, 20),
		ShowBrowser:                   request.ShowBrowser,
		HeadlessOptionalArguments:     mustJSON(cleanStringSlice(request.HeadlessOptionalArguments)),
		UseInstalledChrome:            request.UseInstalledChrome,
		CDPEndpoint:                   nullableString(request.CDPEndpoint),
		ShowActions:                   request.ShowActions,
		Proxy:                         mustJSON(cleanStringSlice(request.Proxy)),
		ProxyInternal:                 request.ProxyInternal,
		EnableProgressBar:             request.EnableProgressBar,
		StatsInterval:                 defaultInt(request.StatsInterval, 5),
		MetricsPort:                   defaultInt(request.MetricsPort, 9092),
		HTTPStats:                     request.HTTPStats,
	}

	if err := s.repository.Create(ctx, task); err != nil {
		return nil, err
	}

	state, err := scanruntime.NewState(task.ID, task.TaskNo, task.Name, len(plan.CollectedTargets), s.runtimeDir)
	if err != nil {
		return nil, err
	}

	runtime := newScanTaskRuntime(state)
	runtime.vulnerabilityQueue = newVulnerabilityQueue(s)
	s.mu.Lock()
	s.states[task.ID] = runtime
	s.mu.Unlock()

	state.Append("info", "task_created", "扫描任务已创建，等待执行")

	s.launchTask(task.ID, plan, runtime)

	return &dto.ScanTaskSummary{
		ID:          task.ID,
		TaskNo:      task.TaskNo,
		Name:        task.Name,
		Description: derefString(task.Description),
		Status:      task.Status,
		CreatedBy:   task.CreatedBy,
	}, nil
}

func (s *scanTaskService) Pause(ctx context.Context, taskID int64) (*dto.PauseScanTaskResponse, error) {
	task, err := s.repository.FindByID(ctx, taskID)
	if err != nil {
		return nil, err
	}

	status := normalizeTaskStatus(task.Status)
	switch status {
	case "success", "failed", "cancelled", "paused":
		return nil, ErrScanTaskNotPausable
	}

	runtime := s.getRuntime(taskID)
	if runtime == nil {
		return nil, ErrScanTaskNotPausable
	}

	alreadyRequested, accepted := runtime.RequestPause()
	if !accepted {
		return nil, ErrScanTaskNotPausable
	}
	if !alreadyRequested {
		runtime.state.Append("info", "task_pause_requested", "已提交暂停请求，等待扫描子进程安全退出")
	}

	return &dto.PauseScanTaskResponse{
		TaskID:         taskID,
		Status:         status,
		PauseRequested: true,
	}, nil
}

func (s *scanTaskService) Cancel(ctx context.Context, taskID int64) (*dto.CancelScanTaskResponse, error) {
	task, err := s.repository.FindByID(ctx, taskID)
	if err != nil {
		return nil, err
	}

	status := normalizeTaskStatus(task.Status)
	switch status {
	case "success", "failed":
		return nil, ErrScanTaskNotCancelable
	case "cancelled":
		return &dto.CancelScanTaskResponse{
			TaskID:          taskID,
			Status:          "cancelled",
			CancelRequested: true,
		}, nil
	case "paused":
		finishedAt := time.Now()
		if err := s.repository.UpdateStatus(ctx, taskID, "cancelled", nil, &finishedAt); err != nil {
			return nil, err
		}
		var state *scanruntime.State
		if runtime := s.getRuntime(taskID); runtime != nil {
			state = runtime.state
		}
		s.archiveStoredResponses(taskID, state)
		if state != nil {
			state.Append("info", "task_cancelled", "扫描任务已取消")
			state.MarkFinished("cancelled", finishedAt, "扫描任务已取消")
		}
		s.cleanupResumeFile(taskID)
		return &dto.CancelScanTaskResponse{
			TaskID:          taskID,
			Status:          "cancelled",
			CancelRequested: true,
		}, nil
	}

	runtime := s.getRuntime(taskID)
	if runtime == nil {
		finishedAt := time.Now()
		if err := s.repository.UpdateStatus(ctx, taskID, "cancelled", nil, &finishedAt); err != nil {
			return nil, err
		}
		s.cleanupResumeFile(taskID)
		if s.logger != nil {
			s.logger.Info("scan task cancelled without runtime state", "task_id", taskID, "previous_status", status)
		}
		return &dto.CancelScanTaskResponse{
			TaskID:          taskID,
			Status:          "cancelled",
			CancelRequested: true,
		}, nil
	}

	alreadyRequested := runtime.RequestCancel()
	if !alreadyRequested {
		runtime.state.Append("info", "task_cancel_requested", "已提交取消请求，等待扫描子进程退出")
	}

	return &dto.CancelScanTaskResponse{
		TaskID:          taskID,
		Status:          status,
		CancelRequested: true,
	}, nil
}

func (s *scanTaskService) Resume(ctx context.Context, taskID int64) (*dto.ResumeScanTaskResponse, error) {
	task, err := s.repository.FindByID(ctx, taskID)
	if err != nil {
		return nil, err
	}

	if normalizeTaskStatus(task.Status) != "paused" {
		return nil, ErrScanTaskNotResumable
	}

	currentRuntime := s.getRuntime(taskID)
	if currentRuntime != nil && !currentRuntime.state.SnapshotProgress().Finished {
		return nil, ErrScanTaskNotResumable
	}

	plan, err := normalizedTaskRequestFromTask(task)
	if err != nil {
		return nil, err
	}

	state, err := scanruntime.NewState(task.ID, task.TaskNo, task.Name, len(plan.CollectedTargets), s.runtimeDir)
	if err != nil {
		return nil, err
	}

	if summary, summaryErr := s.loadPersistedResultSummary(ctx, task.ID); summaryErr != nil {
		state.Close()
		return nil, summaryErr
	} else if summary != nil {
		state.SetResultSummary(*summary)
	}

	state.UpdateProgress(func(snapshot *scanruntime.TaskProgressSnapshot) {
		snapshot.Finished = false
		snapshot.FinishedStatus = "running"
		snapshot.LastUpdatedAt = time.Now()
		snapshot.LastMessage = "扫描任务恢复执行"
	})
	state.Append("info", "task_resume_requested", "扫描任务恢复执行")

	runtime := newScanTaskRuntime(state)
	runtime.vulnerabilityQueue = newVulnerabilityQueue(s)
	if err := s.repository.PrepareForResume(ctx, taskID); err != nil {
		runtime.state.Close()
		runtime.closeVulnerabilityQueue()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrScanTaskNotResumable
		}
		return nil, err
	}

	previousRuntime := s.replaceRuntime(taskID, runtime)
	if previousRuntime != nil && previousRuntime.state != nil {
		previousRuntime.state.Close()
	}

	s.launchTask(taskID, plan, runtime)

	return &dto.ResumeScanTaskResponse{
		TaskID:          taskID,
		Status:          "running",
		ResumeRequested: true,
	}, nil
}

func (s *scanTaskService) List(ctx context.Context, query dto.ListScanTasksQuery) (*dto.PageResult[dto.ScanTaskListItem], error) {
	if query.HasHighRisk {
		return s.listHighRiskTasks(ctx, query)
	}

	page, err := s.repository.List(ctx, query)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	for index := range page.Items {
		item := &page.Items[index]
		progress := s.getProgress(ctx, item.ID, item.Status)
		if state := s.getState(item.ID); state != nil {
			applyRuntimeResultSummaryToListItem(item, state.SnapshotResultSummary())
			progress = state.SnapshotProgress()
		}
		applyProgressSnapshotToListItem(item, progress)
		item.DurationSeconds = calculateTaskDurationSeconds(item.StartedAt, item.FinishedAt, now)
	}

	return page, nil
}

func (s *scanTaskService) ListNameOptions(ctx context.Context, query dto.ListScanTaskNameOptionsQuery) (*dto.PageResult[dto.ScanTaskNameOption], error) {
	return s.repository.ListNameOptions(ctx, query)
}

func (s *scanTaskService) Stats(ctx context.Context) (*dto.ScanTaskStats, error) {
	stats, err := s.repository.Stats(ctx)
	if err != nil {
		return nil, err
	}

	copyStats := *stats
	if copyStats.SavedRequests < 0 {
		copyStats.SavedRequests = 0
	}
	return &copyStats, nil
}

func (s *scanTaskService) listHighRiskTasks(ctx context.Context, query dto.ListScanTasksQuery) (*dto.PageResult[dto.ScanTaskListItem], error) {
	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}

	items, err := s.repository.ListAll(ctx, query)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	filteredItems := make([]dto.ScanTaskListItem, 0, len(items))
	for index := range items {
		item := &items[index]
		progress := s.getProgress(ctx, item.ID, item.Status)
		if state := s.getState(item.ID); state != nil {
			applyRuntimeResultSummaryToListItem(item, state.SnapshotResultSummary())
			progress = state.SnapshotProgress()
		}
		applyProgressSnapshotToListItem(item, progress)
		item.DurationSeconds = calculateTaskDurationSeconds(item.StartedAt, item.FinishedAt, now)
		if !hasHighRiskResult(*item) {
			continue
		}
		filteredItems = append(filteredItems, *item)
	}

	total := len(filteredItems)
	totalPages := 0
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}

	start := (page - 1) * pageSize
	if start >= total {
		return &dto.PageResult[dto.ScanTaskListItem]{
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
			Items:      []dto.ScanTaskListItem{},
		}, nil
	}

	end := start + pageSize
	if end > total {
		end = total
	}

	return &dto.PageResult[dto.ScanTaskListItem]{
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		Items:      filteredItems[start:end],
	}, nil
}

func (s *scanTaskService) Get(ctx context.Context, taskID int64) (*dto.GetScanTaskResponse, error) {
	task, err := s.repository.FindByID(ctx, taskID)
	if err != nil {
		return nil, err
	}
	summary, err := s.buildTaskSummary(ctx, task)
	if err != nil {
		return nil, err
	}
	return &dto.GetScanTaskResponse{
		Task:     summary,
		Progress: s.getProgress(ctx, taskID, task.Status),
	}, nil
}

func (s *scanTaskService) GetLogs(ctx context.Context, taskID, offset int64, limit int, direction string) (*dto.ScanTaskLogsResponse, error) {
	task, err := s.repository.FindByID(ctx, taskID)
	if err != nil {
		return nil, err
	}
	summary, err := s.buildTaskSummary(ctx, task)
	if err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = scanruntime.DefaultLogPageSize
	}

	progress := s.getProgress(ctx, taskID, task.Status)
	state := s.getState(taskID)
	finished := progress.Finished || isFinishedTaskStatus(task.Status)
	useBefore := strings.EqualFold(direction, logDirectionBefore) || (strings.TrimSpace(direction) == "" && finished)

	var page scanruntime.TaskLogsPage
	if useBefore {
		if state != nil {
			page = state.FrontendEventsBefore(offset, limit)
		} else {
			events, hasMore, nextOffset, readErr := scanruntime.ReadFrontendLogEventsBeforeFromFile(s.logFilePath(taskID), offset, limit)
			if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
				return nil, readErr
			}
			page = scanruntime.TaskLogsPage{Events: events, HasMore: hasMore, NextOffset: nextOffset}
		}
	} else if state != nil {
		page = state.EventsSince(offset, limit)
	} else {
		events, hasMore, nextOffset, readErr := scanruntime.ReadLogEventsFromFile(s.logFilePath(taskID), offset, limit)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return nil, readErr
		}
		page = scanruntime.TaskLogsPage{Events: events, HasMore: hasMore, NextOffset: nextOffset}
	}

	return &dto.ScanTaskLogsResponse{
		Task:       summary,
		Progress:   progress,
		Events:     scanruntime.FilterFrontendLogEvents(page.Events),
		NextOffset: page.NextOffset,
		HasMore:    page.HasMore,
	}, nil
}

func (s *scanTaskService) GetResponseArchive(ctx context.Context, taskID int64) (*dto.ScanTaskResponseArchive, error) {
	if _, err := s.repository.FindByID(ctx, taskID); err != nil {
		return nil, err
	}

	zipPath := s.storeResponseZipPath(taskID)
	info, err := os.Lstat(zipPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrScanTaskResponseArchiveNotFound
		}
		return nil, err
	}
	if info.IsDir() || !info.Mode().IsRegular() {
		return nil, ErrScanTaskResponseArchiveNotFound
	}

	return &dto.ScanTaskResponseArchive{
		Path:     zipPath,
		FileName: filepath.Base(zipPath),
		Size:     info.Size(),
	}, nil
}

func (s *scanTaskService) Subscribe(
	ctx context.Context,
	taskID int64,
	offset int64,
) (*dto.ScanTaskSummary, scanruntime.TaskProgressSnapshot, []scanruntime.TaskLogEvent, int64, chan scanruntime.TaskLogEvent, func() dto.ScanTaskSummary, func() scanruntime.TaskProgressSnapshot, func(), error) {
	task, err := s.repository.FindByID(ctx, taskID)
	if err != nil {
		return nil, scanruntime.TaskProgressSnapshot{}, nil, 0, nil, nil, nil, nil, err
	}
	taskSummary, err := s.buildTaskSummary(ctx, task)
	if err != nil {
		return nil, scanruntime.TaskProgressSnapshot{}, nil, 0, nil, nil, nil, nil, err
	}

	state := s.getState(taskID)
	if state == nil || state.SnapshotProgress().Finished {
		progress := s.getProgress(ctx, taskID, task.Status)
		events, _, nextOffset, readErr := scanruntime.ReadLogEventsFromFile(s.logFilePath(taskID), offset, scanruntime.MaxLogPageSize)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return nil, scanruntime.TaskProgressSnapshot{}, nil, 0, nil, nil, nil, nil, readErr
		}
		events = scanruntime.FilterFrontendLogEvents(events)
		return &taskSummary, progress, events, nextOffset, nil, nil, nil, nil, nil
	}

	ch, cancel := state.Subscribe()
	page := state.EventsSince(offset, scanruntime.MaxLogPageSize)
	events := scanruntime.FilterFrontendLogEvents(page.Events)
	progress := state.SnapshotProgress()
	currentTask := func() dto.ScanTaskSummary {
		current := taskSummary
		applyRuntimeResultSummary(&current, state.SnapshotResultSummary())
		return current
	}
	currentProgress := func() scanruntime.TaskProgressSnapshot {
		return state.SnapshotProgress()
	}
	return &taskSummary, progress, events, page.NextOffset, ch, currentTask, currentProgress, cancel, nil
}

func (s *scanTaskService) runTask(taskID int64, plan *normalizedTaskRequest, runtime *scanTaskRuntime) {
	if runtime == nil || runtime.state == nil {
		return
	}
	state := runtime.state
	if runtime.IsCancelRequested() {
		s.finishCancelledTask(taskID, runtime, nil)
		return
	}
	if runtime.IsPauseRequested() {
		s.finishPausedTask(taskID, runtime, nil)
		return
	}

	startedAt := time.Now()
	statusStartedAt := &startedAt
	if task, err := s.repository.FindByID(context.Background(), taskID); err == nil && task.StartedAt != nil {
		startedAt = *task.StartedAt
		statusStartedAt = nil
	} else if err != nil && s.logger != nil {
		s.logger.Error("load task start time failed", "task_id", taskID, "error", err)
	}
	if err := s.repository.UpdateStatus(context.Background(), taskID, "running", statusStartedAt, nil); err != nil {
		if s.logger != nil {
			s.logger.Error("update task status failed", "task_id", taskID, "status", "running", "error", err)
		}
		state.Append("error", "task_db_update_failed", "更新任务状态为 running 失败")
	}

	state.UpdateProgress(func(snapshot *scanruntime.TaskProgressSnapshot) {
		snapshot.LastUpdatedAt = startedAt
		snapshot.LastMessage = "扫描任务开始执行"
		snapshot.Finished = false
		snapshot.FinishedStatus = "running"
	})
	state.Append("info", "task_started", "扫描任务开始执行")

	if runtime.IsCancelRequested() {
		s.finishCancelledTask(taskID, runtime, &startedAt)
		return
	}
	if runtime.IsPauseRequested() {
		s.finishPausedTask(taskID, runtime, &startedAt)
		return
	}

	if err := s.executeTaskPlan(plan, runtime); err != nil {
		if errors.Is(err, context.Canceled) {
			s.finishCancelledTask(taskID, runtime, &startedAt)
			return
		}
		if runtime.IsPauseRequested() {
			s.finishPausedTask(taskID, runtime, &startedAt)
			return
		}
		s.finishFailedTask(taskID, runtime, startedAt)
		return
	}

	s.finishSuccessTask(taskID, runtime, startedAt)
}

func (s *scanTaskService) executeTaskPlan(plan *normalizedTaskRequest, runtime *scanTaskRuntime) error {
	if runtime == nil || runtime.state == nil {
		return errors.New("scan runtime is nil")
	}
	state := runtime.state
	taskDir := filepath.Dir(state.LogFilePath)
	targetsFile := filepath.Join(taskDir, "targets.txt")
	if err := os.WriteFile(targetsFile, []byte(strings.Join(plan.CollectedTargets, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	resumeFile := s.resumeFilePath(state.ID)
	storeResponseDir := s.storeResponseDir(state.ID)

	executable, baseArgs := resolveManScanCommand(s.rootDir)
	args := append(baseArgs, buildScanCLIArgs(plan.Raw, taskDir, targetsFile, resumeFile, storeResponseDir)...)

	cmdCtx, cancel := context.WithCancel(context.Background())
	if !runtime.AttachCancel(cancel) {
		cancel()
		return context.Canceled
	}
	defer cancel()
	defer runtime.ClearCancel()

	cmd := exec.CommandContext(cmdCtx, executable, args...)
	cmd.Dir = s.rootDir
	prepareTaskCommand(cmd)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		if errors.Is(cmdCtx.Err(), context.Canceled) {
			return context.Canceled
		}
		return err
	}
	if !runtime.AttachInterrupt(func() {
		_ = interruptTaskCommand(cmd)
	}) {
		_ = terminateTaskCommand(cmd)
		return context.Canceled
	}
	if !runtime.AttachTerminator(func() {
		_ = terminateTaskCommand(cmd)
	}) {
		_ = terminateTaskCommand(cmd)
		return context.Canceled
	}
	defer runtime.ClearInterrupt()
	defer runtime.ClearTerminator()

	state.Append("info", "process_started", "扫描子进程已启动")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		scanruntime.StreamCommandOutputWithResultHandler(stdoutPipe, state, "stdout", true, s.resultHandler(state.ID, state.TaskName, runtime.vulnerabilityQueue))
	}()
	go func() {
		defer wg.Done()
		scanruntime.StreamCommandOutput(stderrPipe, state, "stderr", false)
	}()

	waitErr := cmd.Wait()
	wg.Wait()
	state.SyncScannerErrors()
	if errors.Is(cmdCtx.Err(), context.Canceled) {
		return context.Canceled
	}
	return waitErr
}

func (s *scanTaskService) finishFailedTask(taskID int64, runtime *scanTaskRuntime, startedAt time.Time) {
	if runtime == nil || runtime.state == nil || !runtime.TryFinalize() {
		return
	}
	runtime.closeVulnerabilityQueue()
	s.archiveStoredResponses(taskID, runtime.state)

	state := runtime.state
	finishedAt := time.Now()
	state.Append("error", "task_failed", "扫描任务执行失败")
	_ = s.repository.UpsertResult(context.Background(), toScanTaskResult(taskID, state.TaskName, &startedAt, finishedAt, state.SnapshotResultSummary()))
	state.MarkFinished("failed", finishedAt, "扫描任务执行失败")
	_ = s.repository.UpdateStatus(context.Background(), taskID, "failed", nil, &finishedAt)
	s.cleanupResumeFile(taskID)
	s.releaseState(taskID, runtime)
}

func (s *scanTaskService) finishSuccessTask(taskID int64, runtime *scanTaskRuntime, startedAt time.Time) {
	if runtime == nil || runtime.state == nil || !runtime.TryFinalize() {
		return
	}
	runtime.closeVulnerabilityQueue()
	s.archiveStoredResponses(taskID, runtime.state)

	state := runtime.state
	finishedAt := time.Now()
	state.Append("info", "task_finished", "扫描任务执行完成")
	_ = s.repository.UpsertResult(context.Background(), toScanTaskResult(taskID, state.TaskName, &startedAt, finishedAt, state.SnapshotResultSummary()))
	state.MarkFinished("success", finishedAt, "扫描任务执行完成")
	_ = s.repository.UpdateStatus(context.Background(), taskID, "success", nil, &finishedAt)
	s.cleanupResumeFile(taskID)
	s.releaseState(taskID, runtime)
}

func (s *scanTaskService) finishCancelledTask(taskID int64, runtime *scanTaskRuntime, startedAt *time.Time) {
	if runtime == nil || runtime.state == nil || !runtime.TryFinalize() {
		return
	}
	runtime.closeVulnerabilityQueue()
	s.archiveStoredResponses(taskID, runtime.state)

	state := runtime.state
	finishedAt := time.Now()
	state.Append("info", "task_cancelled", "扫描任务已取消")
	if startedAt != nil {
		_ = s.repository.UpsertResult(context.Background(), toScanTaskResult(taskID, state.TaskName, startedAt, finishedAt, state.SnapshotResultSummary()))
	}
	state.MarkFinished("cancelled", finishedAt, "扫描任务已取消")
	_ = s.repository.UpdateStatus(context.Background(), taskID, "cancelled", nil, &finishedAt)
	s.cleanupResumeFile(taskID)
	s.releaseState(taskID, runtime)
}

func (s *scanTaskService) finishPausedTask(taskID int64, runtime *scanTaskRuntime, startedAt *time.Time) {
	if runtime == nil || runtime.state == nil || !runtime.TryFinalize() {
		return
	}
	runtime.closeVulnerabilityQueue()

	state := runtime.state
	finishedAt := time.Now()
	state.Append("info", "task_paused", "扫描任务已暂停")
	if startedAt != nil {
		_ = s.repository.UpsertResult(context.Background(), toScanTaskResult(taskID, state.TaskName, startedAt, finishedAt, state.SnapshotResultSummary()))
	}
	state.MarkFinished("paused", finishedAt, "扫描任务已暂停")
	_ = s.repository.UpdateStatus(context.Background(), taskID, "paused", nil, &finishedAt)
	s.releaseState(taskID, runtime)
}

func (s *scanTaskService) getRuntime(taskID int64) *scanTaskRuntime {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.states[taskID]
}

func (s *scanTaskService) getState(taskID int64) *scanruntime.State {
	runtime := s.getRuntime(taskID)
	if runtime == nil {
		return nil
	}
	return runtime.state
}

func (s *scanTaskService) releaseState(taskID int64, runtime *scanTaskRuntime) {
	time.AfterFunc(10*time.Minute, func() {
		s.mu.Lock()
		current := s.states[taskID]
		if current == runtime {
			delete(s.states, taskID)
		}
		s.mu.Unlock()
		if current == runtime && runtime != nil && runtime.state != nil {
			runtime.state.Close()
		}
	})
}

func (s *scanTaskService) getProgress(ctx context.Context, taskID int64, status string) scanruntime.TaskProgressSnapshot {
	if state := s.getState(taskID); state != nil {
		return state.SnapshotProgress()
	}

	data, err := os.ReadFile(s.progressFilePath(taskID))
	if err == nil {
		var snapshot scanruntime.TaskProgressSnapshot
		if json.Unmarshal(data, &snapshot) == nil {
			return snapshot
		}
	}

	finished := isFinishedTaskStatus(status)
	snapshot := scanruntime.TaskProgressSnapshot{
		Finished:       finished,
		FinishedStatus: status,
	}
	if finished && status == "success" {
		snapshot.Percent = 100
	}

	if status == "" {
		task, findErr := s.repository.FindByID(ctx, taskID)
		if findErr == nil {
			snapshot.Finished = isFinishedTaskStatus(task.Status)
			snapshot.FinishedStatus = task.Status
		}
	}

	return snapshot
}

func (s *scanTaskService) logFilePath(taskID int64) string {
	return filepath.Join(s.runtimeDir, fmt.Sprintf("%d", taskID), "events.jsonl")
}

func (s *scanTaskService) matchLogFilePath(taskID int64) string {
	return filepath.Join(s.runtimeDir, fmt.Sprintf("%d", taskID), "match.log")
}

func (s *scanTaskService) progressFilePath(taskID int64) string {
	return filepath.Join(s.runtimeDir, fmt.Sprintf("%d", taskID), "progress.json")
}

func (s *scanTaskService) resumeFilePath(taskID int64) string {
	return filepath.Join(s.runtimeDir, fmt.Sprintf("%d", taskID), "resume.cfg")
}

func (s *scanTaskService) storeResponseDir(taskID int64) string {
	taskName := strconv.FormatInt(taskID, 10)
	if s.rootDir != "" {
		return filepath.Join(s.rootDir, "data", "responses", taskName)
	}
	if s.runtimeDir != "" {
		return filepath.Join(filepath.Dir(s.runtimeDir), "responses", taskName)
	}
	return filepath.Join("data", "responses", taskName)
}

func (s *scanTaskService) storeResponseZipPath(taskID int64) string {
	return s.storeResponseDir(taskID) + ".zip"
}

func (s *scanTaskService) cleanupResumeFile(taskID int64) {
	resumeFile := s.resumeFilePath(taskID)
	if err := os.Remove(resumeFile); err != nil && !errors.Is(err, os.ErrNotExist) && s.logger != nil {
		s.logger.Error("remove resume file failed", "task_id", taskID, "resume_file", resumeFile, "error", err)
	}
}

func (s *scanTaskService) archiveStoredResponses(taskID int64, state *scanruntime.State) {
	sourceDir := s.storeResponseDir(taskID)
	info, err := os.Stat(sourceDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		s.logStoredResponsesArchiveError(taskID, state, err)
		return
	}
	if !info.IsDir() {
		s.logStoredResponsesArchiveError(taskID, state, fmt.Errorf("stored response path is not a directory: %s", sourceDir))
		return
	}

	if state != nil {
		state.Append("info", "stored_responses_archive_started", "请求/响应文件开始压缩归档")
	}
	archived, err := s.archiveStoredResponsesToZip(taskID)
	if err != nil {
		s.logStoredResponsesArchiveError(taskID, state, err)
		return
	}
	if archived && state != nil {
		state.Append("info", "stored_responses_archived", "请求/响应文件压缩归档完成")
	}
}

func (s *scanTaskService) logStoredResponsesArchiveError(taskID int64, state *scanruntime.State, err error) {
	if state != nil {
		state.Append("warn", "stored_responses_archive_failed", "请求/响应文件压缩归档失败")
	}
	if s.logger != nil {
		s.logger.Error("archive stored responses failed", "task_id", taskID, "response_dir", s.storeResponseDir(taskID), "zip_file", s.storeResponseZipPath(taskID), "error", err)
	}
}

func (s *scanTaskService) archiveStoredResponsesToZip(taskID int64) (bool, error) {
	sourceDir := s.storeResponseDir(taskID)
	info, err := os.Stat(sourceDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("stored response path is not a directory: %s", sourceDir)
	}

	zipPath := s.storeResponseZipPath(taskID)
	tmpZipPath := zipPath + ".tmp"
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		return false, err
	}
	if err := os.Remove(tmpZipPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := writeZipDirectory(sourceDir, tmpZipPath, strconv.FormatInt(taskID, 10)); err != nil {
		_ = os.Remove(tmpZipPath)
		return false, err
	}
	if err := os.Remove(zipPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tmpZipPath)
		return false, err
	}
	if err := os.Rename(tmpZipPath, zipPath); err != nil {
		_ = os.Remove(tmpZipPath)
		return false, err
	}
	if err := os.RemoveAll(sourceDir); err != nil {
		return false, err
	}
	return true, nil
}

func writeZipDirectory(sourceDir, zipPath, rootName string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}

	zipWriter := zip.NewWriter(zipFile)
	walkErr := filepath.WalkDir(sourceDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			header.Name = filepath.ToSlash(rootName) + "/"
			_, err = zipWriter.CreateHeader(header)
			return err
		}

		entryName := filepath.ToSlash(filepath.Join(rootName, relPath))
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = entryName

		if entry.IsDir() {
			header.Name += "/"
			_, err = zipWriter.CreateHeader(header)
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		sourceFile, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, sourceFile)
		closeErr := sourceFile.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})

	closeZipErr := zipWriter.Close()
	closeFileErr := zipFile.Close()
	if walkErr != nil {
		return walkErr
	}
	if closeZipErr != nil {
		return closeZipErr
	}
	return closeFileErr
}

func (s *scanTaskService) cleanupDeletedTaskArtifacts(taskIDs []int64) {
	for _, taskID := range taskIDs {
		s.releaseDeletedRuntime(taskID)

		runtimeDir := filepath.Join(s.runtimeDir, fmt.Sprintf("%d", taskID))
		if err := os.RemoveAll(runtimeDir); err != nil && s.logger != nil {
			s.logger.Error("remove deleted scan task runtime files failed", "task_id", taskID, "runtime_dir", runtimeDir, "error", err)
		}
	}
}

func (s *scanTaskService) releaseDeletedRuntime(taskID int64) {
	s.mu.Lock()
	runtime := s.states[taskID]
	delete(s.states, taskID)
	s.mu.Unlock()

	if runtime == nil {
		return
	}

	runtime.TryFinalize()
	runtime.closeVulnerabilityQueue()
	if runtime.state != nil {
		finishedAt := time.Now()
		runtime.state.MarkFinished("cancelled", finishedAt, "扫描任务已删除")
		runtime.state.Close()
	}
}

func normalizeCreateTaskRequest(request dto.CreateScanTaskRequest) (*normalizedTaskRequest, error) {
	collectedTargets := collectTargets(request.Targets, request.InlineTargetsList)
	if len(collectedTargets) == 0 {
		return nil, fmt.Errorf("targets 或 inline_targets_list 至少提供一个目标")
	}

	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = fmt.Sprintf("scan-%s", time.Now().Format("20060102-150405"))
	}

	createdBy := strings.TrimSpace(request.CreatedBy)
	if createdBy == "" {
		createdBy = "anonymous"
	}

	return &normalizedTaskRequest{
		Raw:              request,
		Name:             name,
		Description:      strings.TrimSpace(request.Description),
		CreatedBy:        createdBy,
		CollectedTargets: collectedTargets,
	}, nil
}

func normalizedTaskRequestFromTask(task *entity.ScanTask) (*normalizedTaskRequest, error) {
	if task == nil {
		return nil, fmt.Errorf("任务不存在")
	}

	request := dto.CreateScanTaskRequest{
		Name:                          task.Name,
		Description:                   derefString(task.Description),
		CreatedBy:                     task.CreatedBy,
		Targets:                       decodeJSONStringSlice(task.Targets),
		InlineTargetsList:             derefString(task.InlineTargetsList),
		ExcludeTargets:                decodeJSONStringSlice(task.ExcludeTargets),
		ScanAllIPs:                    task.ScanAllIPs,
		IPVersion:                     decodeJSONStringSlice(task.IPVersion),
		InputFileMode:                 task.InputFileMode,
		NewTemplates:                  task.NewTemplates,
		AutomaticScan:                 task.AutomaticScan,
		EnableGlobalMatchersTemplates: task.EnableGlobalMatchersTemplates,
		Tags:                          decodeJSONStringSlice(task.Tags),
		IncludeIDs:                    decodeJSONStringSlice(task.IncludeIDs),
		Severities:                    decodeJSONStringSlice(task.Severities),
		Protocols:                     decodeJSONStringSlice(task.Protocols),
		StoreResponse:                 task.StoreResponse,
		Timestamp:                     task.Timestamp,
		MatcherStatus:                 task.MatcherStatus,
		CustomHeaders:                 decodeJSONStringSlice(task.CustomHeaders),
		Vars:                          decodeJSONStringSlice(task.Vars),
		FollowRedirects:               task.FollowRedirects,
		FollowHostRedirects:           task.FollowHostRedirects,
		MaxRedirects:                  task.MaxRedirects,
		DisableRedirects:              task.DisableRedirects,
		OfflineHTTP:                   task.OfflineHTTP,
		ForceAttemptHTTP2:             task.ForceAttemptHTTP2,
		SNI:                           derefString(task.SNI),
		AllowLocalFileAccess:          task.AllowLocalFileAccess,
		AttackType:                    derefString(task.AttackType),
		SourceIP:                      derefString(task.SourceIP),
		ResponseReadSize:              task.ResponseReadSize,
		ResponseSaveSize:              task.ResponseSaveSize,
		TLSImpersonate:                task.TLSImpersonate,
		RateLimit:                     task.RateLimit,
		RateLimitDuration:             task.RateLimitDuration,
		BulkSize:                      task.BulkSize,
		TemplateThreads:               task.TemplateThreads,
		HeadlessBulkSize:              task.HeadlessBulkSize,
		HeadlessTemplateThreads:       task.HeadlessTemplateThreads,
		JSConcurrency:                 task.JSConcurrency,
		PayloadConcurrency:            task.PayloadConcurrency,
		ProbeConcurrency:              task.ProbeConcurrency,
		Timeout:                       task.Timeout,
		Retries:                       task.Retries,
		MaxHostError:                  task.MaxHostError,
		NoHostErrors:                  task.NoHostErrors,
		Project:                       task.Project,
		ProjectPath:                   derefString(task.ProjectPath),
		ScanStrategy:                  derefString(task.ScanStrategy),
		DisableHTTPProbe:              task.DisableHTTPProbe,
		Headless:                      task.Headless,
		PageTimeout:                   task.PageTimeout,
		ShowBrowser:                   task.ShowBrowser,
		HeadlessOptionalArguments:     decodeJSONStringSlice(task.HeadlessOptionalArguments),
		UseInstalledChrome:            task.UseInstalledChrome,
		CDPEndpoint:                   derefString(task.CDPEndpoint),
		ShowActions:                   task.ShowActions,
		Proxy:                         decodeJSONStringSlice(task.Proxy),
		ProxyInternal:                 task.ProxyInternal,
		EnableProgressBar:             task.EnableProgressBar,
		StatsInterval:                 task.StatsInterval,
		MetricsPort:                   task.MetricsPort,
		HTTPStats:                     task.HTTPStats,
	}
	return normalizeCreateTaskRequest(request)
}

func collectTargets(targets []string, inline string) []string {
	result := make([]string, 0, len(targets)+8)
	seen := make(map[string]struct{})

	appendTarget := func(value string) {
		value = normalizeTarget(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	for _, target := range targets {
		appendTarget(target)
	}
	for _, line := range strings.Split(inline, "\n") {
		appendTarget(line)
	}

	return result
}

func normalizeTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	parsed, err := url.Parse(value)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
		if parsed.Path == "" && parsed.RawPath == "/" {
			parsed.RawPath = ""
		} else if parsed.RawPath != "" {
			parsed.RawPath = strings.TrimRight(parsed.RawPath, "/")
		}
		return parsed.String()
	}

	return strings.TrimRight(value, "/")
}

func resolveManScanCommand(rootDir string) (string, []string) {
	binaryPath := filepath.Join(rootDir, "manscan")
	if info, err := os.Stat(binaryPath); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
		return binaryPath, nil
	}
	return "go", []string{"run", "./cmd/nuclei"}
}

func buildScanCLIArgs(request dto.CreateScanTaskRequest, taskDir, targetsFile, resumeFile, storeResponseDir string) []string {
	args := []string{
		"-l", targetsFile,
		"-j",
		"-stats-json",
		"-stats",
		"-nc",
		"-v",
	}

	appendFlag := func(flag string, values ...string) {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value != "" {
				args = append(args, flag, value)
			}
		}
	}

	appendBool := func(enabled bool, flag string) {
		if enabled {
			args = append(args, flag)
		}
	}

	appendInt := func(value int, flag string) {
		if value > 0 {
			args = append(args, flag, strconv.Itoa(value))
		}
	}

	appendBool(request.ScanAllIPs, "-sa")
	appendBool(request.NewTemplates, "-nt")
	appendBool(request.AutomaticScan, "-as")
	appendBool(request.EnableGlobalMatchersTemplates, "-egm")
	appendBool(request.StoreResponse, "-sresp")
	if request.StoreResponse {
		appendFlag("-srd", storeResponseDir)
	}
	appendBool(request.Timestamp, "-ts")
	appendBool(request.MatcherStatus, "-ms")
	appendBool(request.FollowRedirects, "-fr")
	appendBool(request.FollowHostRedirects, "-fhr")
	appendBool(request.DisableRedirects, "-dr")
	appendBool(request.OfflineHTTP, "--passive")
	appendBool(request.ForceAttemptHTTP2, "-fh2")
	appendBool(request.AllowLocalFileAccess, "-lfa")
	appendBool(request.TLSImpersonate, "-tlsi")
	appendBool(request.NoHostErrors, "-nmhe")
	appendBool(request.Project, "--project")
	appendBool(request.DisableHTTPProbe, "-nh")
	appendBool(request.Headless, "--headless")
	appendBool(request.ShowBrowser, "-sb")
	appendBool(request.UseInstalledChrome, "-sc")
	appendBool(request.ShowActions, "-lha")
	appendBool(request.ProxyInternal, "-pi")
	appendBool(request.EnableProgressBar, "--stats")
	appendBool(request.HTTPStats, "-hps")

	appendInt(defaultInt(request.StatsInterval, 5), "-si")
	appendInt(defaultInt(request.MetricsPort, 9092), "-mp")
	appendInt(request.MaxRedirects, "-mr")
	appendInt(request.ResponseReadSize, "-rsr")
	appendInt(defaultInt(request.ResponseSaveSize, 1048576), "-rss")
	appendInt(defaultInt(request.RateLimit, 150), "-rl")
	if duration := defaultInt64(request.RateLimitDuration, 1000); duration > 0 {
		args = append(args, "-rld", fmt.Sprintf("%dms", duration))
	}
	appendInt(defaultInt(request.BulkSize, 25), "-bs")
	appendInt(defaultInt(request.TemplateThreads, 25), "-c")
	appendInt(defaultInt(request.HeadlessBulkSize, 10), "-hbs")
	appendInt(defaultInt(request.HeadlessTemplateThreads, 10), "-headc")
	appendInt(defaultInt(request.JSConcurrency, 120), "-jsc")
	appendInt(defaultInt(request.PayloadConcurrency, 25), "-pc")
	appendInt(defaultInt(request.ProbeConcurrency, 50), "-prc")
	appendInt(defaultInt(request.Timeout, 10), "--timeout")
	appendInt(defaultInt(request.Retries, 1), "--retries")
	appendInt(defaultInt(request.MaxHostError, 30), "-mhe")
	appendInt(defaultInt(request.PageTimeout, 20), "--page-timeout")

	if values := cleanStringSlice(request.ExcludeTargets); len(values) > 0 {
		args = append(args, "-eh", strings.Join(values, ","))
	}
	if values := cleanStringSlice(request.IPVersion); len(values) > 0 {
		args = append(args, "-iv", strings.Join(values, ","))
	}
	if values := cleanStringSlice(request.Tags); len(values) > 0 {
		args = append(args, "--tags", strings.Join(values, ","))
	}
	if values := cleanStringSlice(request.IncludeIDs); len(values) > 0 {
		args = append(args, "-id", strings.Join(values, ","))
	}
	if values := cleanStringSlice(request.Severities); len(values) > 0 {
		args = append(args, "-s", strings.Join(values, ","))
	}
	if values := templateprotocol.NormalizeList(request.Protocols); len(values) > 0 {
		args = append(args, "-pt", strings.Join(values, ","))
	}
	for _, header := range cleanStringSlice(request.CustomHeaders) {
		args = append(args, "-H", header)
	}
	for _, variable := range cleanStringSlice(request.Vars) {
		args = append(args, "-V", variable)
	}
	appendFlag("--sni", request.SNI)
	appendFlag("-at", request.AttackType)
	appendFlag("-sip", request.SourceIP)
	appendFlag("--project-path", request.ProjectPath)
	appendFlag("-ss", firstNonEmpty(request.ScanStrategy, "auto"))
	appendFlag("-resume", resumeFile)
	for _, item := range cleanStringSlice(request.HeadlessOptionalArguments) {
		args = append(args, "-ho", item)
	}
	appendFlag("-cdpe", request.CDPEndpoint)
	for _, proxy := range cleanStringSlice(request.Proxy) {
		args = append(args, "-p", proxy)
	}

	args = append(args,
		"-elog", filepath.Join(taskDir, "error.log"),
	)
	return args
}

func toScanTaskSummary(task *entity.ScanTask, result *entity.ScanTaskResult) dto.ScanTaskSummary {
	summary := dto.ScanTaskSummary{
		ID:          task.ID,
		TaskNo:      task.TaskNo,
		Name:        task.Name,
		Description: derefString(task.Description),
		Status:      task.Status,
		CreatedBy:   task.CreatedBy,
		StartedAt:   task.StartedAt,
		FinishedAt:  task.FinishedAt,
	}
	if result != nil {
		summary.CriticalCount = result.CriticalCount
		summary.HighCount = result.HighCount
		summary.MediumCount = result.MediumCount
		summary.LowCount = result.LowCount
		summary.InfoCount = result.InfoCount
		summary.TechCount = result.TechCount
		summary.PluginCount = result.PluginCount
		summary.TargetCount = result.TargetCount
	}
	return summary
}

func applyRuntimeResultSummary(summary *dto.ScanTaskSummary, result scanruntime.ResultSummary) {
	summary.CriticalCount = result.CriticalCount
	summary.HighCount = result.HighCount
	summary.MediumCount = result.MediumCount
	summary.LowCount = result.LowCount
	summary.InfoCount = result.InfoCount
	summary.TechCount = result.TechCount
	summary.PluginCount = result.PluginCount
	summary.TargetCount = result.TargetCount
}

func applyRuntimeResultSummaryToListItem(item *dto.ScanTaskListItem, result scanruntime.ResultSummary) {
	item.CriticalCount = result.CriticalCount
	item.HighCount = result.HighCount
	item.MediumCount = result.MediumCount
	item.LowCount = result.LowCount
	item.InfoCount = result.InfoCount
	item.TechCount = result.TechCount
	item.PluginCount = result.PluginCount
	item.TargetCount = result.TargetCount
	item.TotalRequests = result.TotalRequests
	item.RealRequests = result.RealRequests
}

func applyProgressSnapshotToListItem(item *dto.ScanTaskListItem, progress scanruntime.TaskProgressSnapshot) {
	if progress.TotalRequests > 0 {
		item.TotalRequests = progress.TotalRequests
	}
	if progress.Requests > 0 {
		item.RealRequests = progress.Requests
	}
	item.ProgressPercent = progress.Percent
	item.LastMessage = progress.LastMessage
}

func calculateTaskDurationSeconds(startedAt, finishedAt *time.Time, now time.Time) int64 {
	if startedAt == nil {
		return 0
	}
	end := now
	if finishedAt != nil {
		end = *finishedAt
	}
	if end.Before(*startedAt) {
		return 0
	}
	return int64(end.Sub(*startedAt).Seconds())
}

func hasHighRiskResult(item dto.ScanTaskListItem) bool {
	return item.CriticalCount > 0 || item.HighCount > 0
}

func calculateSavedRequests(totalRequests, realRequests int64) int64 {
	saved := totalRequests - realRequests
	if saved < 0 {
		return 0
	}
	return saved
}

func (s *scanTaskService) buildTaskSummary(ctx context.Context, task *entity.ScanTask) (dto.ScanTaskSummary, error) {
	summary := toScanTaskSummary(task, nil)
	if state := s.getState(task.ID); state != nil {
		applyRuntimeResultSummary(&summary, state.SnapshotResultSummary())
		return summary, nil
	}

	result, err := s.findTaskResult(ctx, task.ID)
	if err != nil {
		return dto.ScanTaskSummary{}, err
	}
	if result != nil {
		summary = toScanTaskSummary(task, result)
	}
	if deduped, ok := s.loadDedupedResultSummaryFromMatchLog(task.ID, summary.TargetCount); ok {
		applyRuntimeResultSummary(&summary, mergeResultSummaryCounts(deduped, entityResultRequestSummary(result)))
	}
	return summary, nil
}

func (s *scanTaskService) findTaskResult(ctx context.Context, taskID int64) (*entity.ScanTaskResult, error) {
	result, err := s.repository.FindResultByTaskID(ctx, taskID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return result, nil
}

func (s *scanTaskService) loadPersistedResultSummary(ctx context.Context, taskID int64) (*scanruntime.ResultSummary, error) {
	result, err := s.findTaskResult(ctx, taskID)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	summary := entityResultSummary(result)
	if deduped, ok := s.loadDedupedResultSummaryFromMatchLog(taskID, summary.TargetCount); ok {
		summary = mergeResultSummaryCounts(deduped, summary)
	}
	return &summary, nil
}

func entityResultSummary(result *entity.ScanTaskResult) scanruntime.ResultSummary {
	if result == nil {
		return scanruntime.ResultSummary{}
	}
	return scanruntime.ResultSummary{
		CriticalCount: result.CriticalCount,
		HighCount:     result.HighCount,
		MediumCount:   result.MediumCount,
		LowCount:      result.LowCount,
		InfoCount:     result.InfoCount,
		TechCount:     result.TechCount,
		PluginCount:   result.PluginCount,
		TargetCount:   result.TargetCount,
		TotalRequests: result.TotalRequests,
		RealRequests:  result.RealRequests,
	}
}

func entityResultRequestSummary(result *entity.ScanTaskResult) scanruntime.ResultSummary {
	if result == nil {
		return scanruntime.ResultSummary{}
	}
	return scanruntime.ResultSummary{
		PluginCount:   result.PluginCount,
		TargetCount:   result.TargetCount,
		TotalRequests: result.TotalRequests,
		RealRequests:  result.RealRequests,
	}
}

func mergeResultSummaryCounts(counts, requestStats scanruntime.ResultSummary) scanruntime.ResultSummary {
	counts.PluginCount = requestStats.PluginCount
	if requestStats.TargetCount > counts.TargetCount {
		counts.TargetCount = requestStats.TargetCount
	}
	counts.TotalRequests = requestStats.TotalRequests
	counts.RealRequests = requestStats.RealRequests
	return counts
}

func (s *scanTaskService) loadDedupedResultSummaryFromMatchLog(taskID int64, targetCount int) (scanruntime.ResultSummary, bool) {
	summary, ok, err := scanruntime.ReadResultSummaryFromMatchLog(s.matchLogFilePath(taskID), targetCount)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && s.logger != nil {
			s.logger.Error("read match log summary failed", "task_id", taskID, "error", err)
		}
		return scanruntime.ResultSummary{}, false
	}
	return summary, ok
}

func (s *scanTaskService) launchTask(taskID int64, plan *normalizedTaskRequest, runtime *scanTaskRuntime) {
	if s.taskRunner != nil {
		s.taskRunner(taskID, plan, runtime)
		return
	}
	go s.runTask(taskID, plan, runtime)
}

func (s *scanTaskService) replaceRuntime(taskID int64, runtime *scanTaskRuntime) *scanTaskRuntime {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous := s.states[taskID]
	if runtime == nil {
		delete(s.states, taskID)
		return previous
	}
	s.states[taskID] = runtime
	return previous
}

func toScanTaskResult(taskID int64, taskName string, startedAt *time.Time, finishedAt time.Time, summary scanruntime.ResultSummary) *entity.ScanTaskResult {
	return &entity.ScanTaskResult{
		TaskID:        taskID,
		TaskName:      taskName,
		CriticalCount: summary.CriticalCount,
		HighCount:     summary.HighCount,
		MediumCount:   summary.MediumCount,
		LowCount:      summary.LowCount,
		InfoCount:     summary.InfoCount,
		TechCount:     summary.TechCount,
		PluginCount:   summary.PluginCount,
		TargetCount:   summary.TargetCount,
		TotalRequests: summary.TotalRequests,
		RealRequests:  summary.RealRequests,
		CreatedAt:     startedAt,
		FinishedAt:    &finishedAt,
	}
}

func isFinishedTaskStatus(status string) bool {
	switch normalizeTaskStatus(status) {
	case "success", "failed", "cancelled", "paused":
		return true
	default:
		return false
	}
}

func normalizeTaskStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

func normalizeScanTaskIDs(ids []int64) ([]int64, error) {
	if len(ids) == 0 || len(ids) > maxBatchScanTaskIDs {
		return nil, ErrInvalidScanTaskIDs
	}

	result := make([]int64, 0, len(ids))
	seen := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		if id <= 0 {
			return nil, ErrInvalidScanTaskIDs
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	if len(result) == 0 {
		return nil, ErrInvalidScanTaskIDs
	}
	return result, nil
}

func isDeletableScanTaskStatus(status string) bool {
	switch normalizeTaskStatus(status) {
	case "success", "failed", "cancelled", "paused":
		return true
	default:
		return false
	}
}

func nullableString(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func cleanStringSlice(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func decodeJSONStringSlice(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	var decoded []string
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return nil
	}
	return cleanStringSlice(decoded)
}

func mustJSON(value interface{}) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func defaultInt(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func defaultInt64(value, fallback int64) int64 {
	if value <= 0 {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func newScanTaskRuntime(state *scanruntime.State) *scanTaskRuntime {
	return &scanTaskRuntime{state: state}
}

func (r *scanTaskRuntime) closeVulnerabilityQueue() {
	if r == nil || r.vulnerabilityQueue == nil {
		return
	}
	r.vulnerabilityQueue.CloseAndWait()
	r.vulnerabilityQueue = nil
}

func (r *scanTaskRuntime) RequestPause() (bool, bool) {
	if r == nil {
		return false, false
	}

	r.mu.Lock()
	if r.finalized || r.cancelRequested {
		r.mu.Unlock()
		return false, false
	}
	alreadyRequested := r.pauseRequested
	r.pauseRequested = true
	interrupt := r.interrupt
	r.mu.Unlock()

	if interrupt != nil {
		interrupt()
	}
	return alreadyRequested, true
}

func (r *scanTaskRuntime) RequestCancel() bool {
	if r == nil {
		return false
	}

	r.mu.Lock()
	alreadyRequested := r.cancelRequested
	r.cancelRequested = true
	r.pauseRequested = false
	cancel := r.cancel
	terminate := r.terminate
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if terminate != nil {
		terminate()
	}
	return alreadyRequested
}

func (r *scanTaskRuntime) IsPauseRequested() bool {
	if r == nil {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pauseRequested && !r.cancelRequested
}

func (r *scanTaskRuntime) IsCancelRequested() bool {
	if r == nil {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancelRequested
}

func (r *scanTaskRuntime) AttachCancel(cancel context.CancelFunc) bool {
	if r == nil {
		return false
	}

	r.mu.Lock()
	if r.finalized {
		r.mu.Unlock()
		return false
	}
	r.cancel = cancel
	cancelRequested := r.cancelRequested
	r.mu.Unlock()

	if cancelRequested && cancel != nil {
		cancel()
	}
	return true
}

func (r *scanTaskRuntime) AttachInterrupt(interrupt func()) bool {
	if r == nil {
		return false
	}

	r.mu.Lock()
	if r.finalized {
		r.mu.Unlock()
		return false
	}
	r.interrupt = interrupt
	pauseRequested := r.pauseRequested && !r.cancelRequested
	r.mu.Unlock()

	if pauseRequested && interrupt != nil {
		interrupt()
	}
	return true
}

func (r *scanTaskRuntime) ClearInterrupt() {
	if r == nil {
		return
	}

	r.mu.Lock()
	r.interrupt = nil
	r.mu.Unlock()
}

func (r *scanTaskRuntime) ClearCancel() {
	if r == nil {
		return
	}

	r.mu.Lock()
	r.cancel = nil
	r.mu.Unlock()
}

func (r *scanTaskRuntime) AttachTerminator(terminate func()) bool {
	if r == nil {
		return false
	}

	r.mu.Lock()
	if r.finalized {
		r.mu.Unlock()
		return false
	}
	r.terminate = terminate
	cancelRequested := r.cancelRequested
	r.mu.Unlock()

	if cancelRequested && terminate != nil {
		terminate()
	}
	return true
}

func (r *scanTaskRuntime) ClearTerminator() {
	if r == nil {
		return
	}

	r.mu.Lock()
	r.terminate = nil
	r.mu.Unlock()
}

func (r *scanTaskRuntime) TryFinalize() bool {
	if r == nil {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finalized {
		return false
	}
	r.finalized = true
	r.cancel = nil
	r.interrupt = nil
	r.terminate = nil
	return true
}
