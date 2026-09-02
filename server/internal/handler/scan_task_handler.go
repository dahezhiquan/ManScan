package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/pkg/scanruntime"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type ScanTaskHandler interface {
	Create(c *gin.Context)
	Rescan(c *gin.Context)
	Delete(c *gin.Context)
	Pause(c *gin.Context)
	Resume(c *gin.Context)
	Cancel(c *gin.Context)
	List(c *gin.Context)
	NameOptions(c *gin.Context)
	Stats(c *gin.Context)
	Get(c *gin.Context)
	Logs(c *gin.Context)
	Stream(c *gin.Context)
}

type scanTaskHandler struct {
	service service.ScanTaskService
}

func NewScanTaskHandler(scanTaskService service.ScanTaskService) ScanTaskHandler {
	return &scanTaskHandler{service: scanTaskService}
}

func (h *scanTaskHandler) Create(c *gin.Context) {
	var request dto.CreateScanTaskRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "请求体解析失败")
		return
	}

	task, err := h.service.Create(c.Request.Context(), request)
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}

	response.SuccessWithStatus(c, http.StatusAccepted, gin.H{
		"task":     task,
		"log_api":  fmt.Sprintf("/api/v1/scans/%d/logs", task.ID),
		"stream":   fmt.Sprintf("/api/v1/scans/%d/stream", task.ID),
		"task_api": fmt.Sprintf("/api/v1/scans/%d", task.ID),
	})
}

func (h *scanTaskHandler) Rescan(c *gin.Context) {
	taskID, err := parseTaskID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}

	task, serviceErr := h.service.Rescan(c.Request.Context(), taskID)
	if serviceErr != nil {
		if errors.Is(serviceErr, gorm.ErrRecordNotFound) {
			response.Fail(c, errcode.NotFound, "任务不存在")
			return
		}
		if errors.Is(serviceErr, service.ErrScanTaskInvalidConfiguration) {
			response.Fail(c, errcode.InvalidParams, serviceErr.Error())
			return
		}
		response.Fail(c, errcode.InternalServerError, "重新扫描任务失败")
		return
	}

	response.SuccessWithStatus(c, http.StatusAccepted, gin.H{
		"task":     task,
		"log_api":  fmt.Sprintf("/api/v1/scans/%d/logs", task.ID),
		"stream":   fmt.Sprintf("/api/v1/scans/%d/stream", task.ID),
		"task_api": fmt.Sprintf("/api/v1/scans/%d", task.ID),
	})
}

func (h *scanTaskHandler) Delete(c *gin.Context) {
	var request dto.DeleteScanTaskRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "请求体解析失败")
		return
	}

	data, serviceErr := h.service.Delete(c.Request.Context(), request)
	if serviceErr != nil {
		if errors.Is(serviceErr, gorm.ErrRecordNotFound) {
			response.Fail(c, errcode.NotFound, "任务不存在")
			return
		}
		if errors.Is(serviceErr, service.ErrInvalidScanTaskIDs) {
			response.Fail(c, errcode.InvalidParams, "id 或 ids 必须包含 1-1000 个大于 0 的扫描任务 id")
			return
		}
		if errors.Is(serviceErr, service.ErrScanTaskNotDeletable) {
			response.Fail(c, errcode.InvalidParams, "仅支持删除已结束或已暂停的扫描任务，请先取消仍在执行的任务")
			return
		}
		response.Fail(c, errcode.InternalServerError, "删除扫描任务失败")
		return
	}

	response.Success(c, data)
}

func (h *scanTaskHandler) Cancel(c *gin.Context) {
	taskID, err := parseTaskID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}

	data, serviceErr := h.service.Cancel(c.Request.Context(), taskID)
	if serviceErr != nil {
		if serviceErr == gorm.ErrRecordNotFound {
			response.Fail(c, errcode.NotFound, "任务不存在")
			return
		}
		if serviceErr == service.ErrScanTaskNotCancelable {
			response.Fail(c, errcode.InvalidParams, serviceErr.Error())
			return
		}
		response.Fail(c, errcode.InternalServerError, "取消任务失败")
		return
	}

	response.SuccessWithStatus(c, http.StatusAccepted, data)
}

func (h *scanTaskHandler) Pause(c *gin.Context) {
	taskID, err := parseTaskID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}

	data, serviceErr := h.service.Pause(c.Request.Context(), taskID)
	if serviceErr != nil {
		if serviceErr == gorm.ErrRecordNotFound {
			response.Fail(c, errcode.NotFound, "任务不存在")
			return
		}
		if serviceErr == service.ErrScanTaskNotPausable {
			response.Fail(c, errcode.InvalidParams, serviceErr.Error())
			return
		}
		response.Fail(c, errcode.InternalServerError, "暂停任务失败")
		return
	}

	response.SuccessWithStatus(c, http.StatusAccepted, data)
}

func (h *scanTaskHandler) Resume(c *gin.Context) {
	taskID, err := parseTaskID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}

	data, serviceErr := h.service.Resume(c.Request.Context(), taskID)
	if serviceErr != nil {
		if serviceErr == gorm.ErrRecordNotFound {
			response.Fail(c, errcode.NotFound, "任务不存在")
			return
		}
		if serviceErr == service.ErrScanTaskNotResumable {
			response.Fail(c, errcode.InvalidParams, serviceErr.Error())
			return
		}
		response.Fail(c, errcode.InternalServerError, "恢复任务失败")
		return
	}

	response.SuccessWithStatus(c, http.StatusAccepted, data)
}

func (h *scanTaskHandler) List(c *gin.Context) {
	page, err := parsePositiveIntQuery(c.Query("page"), 1)
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "page 参数必须是大于等于 1 的整数")
		return
	}
	pageSize, err := parsePositiveIntQuery(c.Query("page_size"), 10)
	if err != nil || pageSize > 100 {
		response.Fail(c, errcode.InvalidParams, "page_size 参数必须在 1-100 之间")
		return
	}
	hasHighRisk, err := parseBoolQuery(c.Query("has_high_risk"), false)
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "has_high_risk 参数必须是布尔值")
		return
	}

	data, serviceErr := h.service.List(c.Request.Context(), dto.ListScanTasksQuery{
		Page:           page,
		PageSize:       pageSize,
		Keyword:        strings.TrimSpace(c.Query("keyword")),
		Statuses:       parseMultiValueQuery(c, "status"),
		ScanStrategies: parseMultiValueQuery(c, "scan_strategy"),
		CreatedBy:      strings.TrimSpace(c.Query("created_by")),
		HasHighRisk:    hasHighRisk,
	})
	if serviceErr != nil {
		response.Fail(c, errcode.InternalServerError, "获取任务列表失败")
		return
	}

	response.Success(c, data)
}

func (h *scanTaskHandler) NameOptions(c *gin.Context) {
	page, err := parsePositiveIntQuery(c.Query("page"), 1)
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "page 参数必须是大于等于 1 的整数")
		return
	}
	pageSize, err := parsePositiveIntQuery(c.Query("page_size"), 20)
	if err != nil || pageSize > 100 {
		response.Fail(c, errcode.InvalidParams, "page_size 参数必须在 1-100 之间")
		return
	}

	data, serviceErr := h.service.ListNameOptions(c.Request.Context(), dto.ListScanTaskNameOptionsQuery{
		Page:     page,
		PageSize: pageSize,
		Keyword:  strings.TrimSpace(c.Query("keyword")),
	})
	if serviceErr != nil {
		response.Fail(c, errcode.InternalServerError, "获取扫描任务名称失败")
		return
	}

	response.Success(c, data)
}

func (h *scanTaskHandler) Stats(c *gin.Context) {
	data, serviceErr := h.service.Stats(c.Request.Context())
	if serviceErr != nil {
		response.Fail(c, errcode.InternalServerError, "获取扫描任务统计失败")
		return
	}

	response.Success(c, data)
}

func (h *scanTaskHandler) Get(c *gin.Context) {
	taskID, err := parseTaskID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}

	data, serviceErr := h.service.Get(c.Request.Context(), taskID)
	if serviceErr != nil {
		if serviceErr == gorm.ErrRecordNotFound {
			response.Fail(c, errcode.NotFound, "任务不存在")
			return
		}
		response.Fail(c, errcode.InternalServerError, "获取任务失败")
		return
	}

	response.Success(c, data)
}

func (h *scanTaskHandler) Logs(c *gin.Context) {
	taskID, err := parseTaskID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}

	offset := int64(0)
	if raw := strings.TrimSpace(c.Query("offset")); raw != "" {
		offset, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || offset < 0 {
			response.Fail(c, errcode.InvalidParams, "offset 必须是大于等于 0 的整数")
			return
		}
	}

	limit := 200
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		parsedLimit, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsedLimit <= 0 || parsedLimit > 1000 {
			response.Fail(c, errcode.InvalidParams, "limit 必须在 1-1000 之间")
			return
		}
		limit = parsedLimit
	}

	direction := strings.ToLower(strings.TrimSpace(c.Query("direction")))
	switch direction {
	case "", "forward", "before":
	default:
		response.Fail(c, errcode.InvalidParams, "direction 只能是 forward 或 before")
		return
	}

	data, serviceErr := h.service.GetLogs(c.Request.Context(), taskID, offset, limit, direction)
	if serviceErr != nil {
		if serviceErr == gorm.ErrRecordNotFound {
			response.Fail(c, errcode.NotFound, "任务不存在")
			return
		}
		response.Fail(c, errcode.InternalServerError, "获取任务日志失败")
		return
	}

	response.Success(c, data)
}

func (h *scanTaskHandler) Stream(c *gin.Context) {
	taskID, err := parseTaskID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}

	offset := int64(0)
	if raw := strings.TrimSpace(c.Query("offset")); raw != "" {
		offset, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || offset < 0 {
			response.Fail(c, errcode.InvalidParams, "offset 必须是大于等于 0 的整数")
			return
		}
	}

	task, progress, events, nextOffset, ch, taskSnapshot, progressSnapshot, cancel, serviceErr := h.service.Subscribe(c.Request.Context(), taskID, offset)
	if serviceErr != nil {
		if serviceErr == gorm.ErrRecordNotFound {
			response.Fail(c, errcode.NotFound, "任务不存在")
			return
		}
		response.Fail(c, errcode.InternalServerError, "建立日志流失败")
		return
	}
	if cancel != nil {
		defer cancel()
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		response.Fail(c, errcode.InternalServerError, "当前连接不支持流式输出")
		return
	}

	sendSSE := func(event string, payload interface{}) error {
		data, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return marshalErr
		}
		if _, writeErr := fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, data); writeErr != nil {
			return writeErr
		}
		flusher.Flush()
		return nil
	}

	if err := sendSSE("snapshot", gin.H{
		"task":       task,
		"progress":   progress,
		"events":     events,
		"nextOffset": nextOffset,
	}); err != nil {
		return
	}

	if ch == nil {
		_ = sendSSE("complete", gin.H{"task_id": taskID, "status": task.Status})
		return
	}

	currentOffset := nextOffset
	if currentOffset < offset {
		currentOffset = offset
	}
	for {
		select {
		case <-c.Request.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				_ = sendSSE("complete", gin.H{"task_id": taskID, "status": progress.FinishedStatus})
				return
			}
			if event.Seq <= currentOffset {
				continue
			}
			currentOffset = event.Seq
			if scanruntime.ShouldHideFrontendLogEvent(event) {
				continue
			}
			payload := gin.H{
				"task_id":    taskID,
				"seq":        event.Seq,
				"time":       event.Time,
				"level":      event.Level,
				"type":       event.Type,
				"message":    event.Message,
				"event":      event,
				"nextOffset": currentOffset,
			}
			if event.Type == "progress" && progressSnapshot != nil {
				progress = progressSnapshot()
				payload["progress"] = progress
			}
			if (event.Type == "progress" || event.Type == "result") && taskSnapshot != nil {
				payload["task"] = taskSnapshot()
			}
			if err := sendSSE("event", payload); err != nil {
				return
			}
		}
	}
}

func parseTaskID(raw string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("任务 id 不合法")
	}
	return value, nil
}

func parsePositiveIntQuery(raw string, defaultValue int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultValue, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid positive int")
	}
	return value, nil
}

func parseBoolQuery(raw string, defaultValue bool) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, err
	}
	return value, nil
}
