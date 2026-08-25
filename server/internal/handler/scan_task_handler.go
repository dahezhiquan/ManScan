package handler

import (
	"encoding/json"
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

	data, serviceErr := h.service.GetLogs(c.Request.Context(), taskID, offset, limit)
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

	task, progress, events, nextOffset, ch, taskSnapshot, progressSnapshot, cancel, serviceErr := h.service.Subscribe(c.Request.Context(), taskID)
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
	for {
		select {
		case <-c.Request.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				_ = sendSSE("complete", gin.H{"task_id": taskID, "status": progress.FinishedStatus})
				return
			}
			if event.Seq < currentOffset {
				continue
			}
			currentOffset = event.Seq + 1
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
