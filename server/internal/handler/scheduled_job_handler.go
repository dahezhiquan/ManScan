package handler

import (
	"errors"
	"strconv"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type ScheduledJobHandler interface {
	Create(*gin.Context)
	List(*gin.Context)
	Get(*gin.Context)
	Update(*gin.Context)
	Delete(*gin.Context)
	Trigger(*gin.Context)
	ListRuns(*gin.Context)
	GetRun(*gin.Context)
}

type scheduledJobHandler struct{ service service.ScheduledJobService }

// NewScheduledJobHandler 创建定时任务控制器。
func NewScheduledJobHandler(svc service.ScheduledJobService) ScheduledJobHandler {
	return &scheduledJobHandler{service: svc}
}

func (h *scheduledJobHandler) Create(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可管理定时任务")
		return
	}
	var request dto.CreateScheduledJobRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "请求体解析失败")
		return
	}
	data, err := h.service.Create(c.Request.Context(), request)
	if err != nil {
		handleScheduledJobError(c, err, "新增定时任务失败")
		return
	}
	response.Success(c, data)
}

func (h *scheduledJobHandler) List(c *gin.Context) {
	page, pageSize, ok := parseScheduledJobPage(c)
	if !ok {
		return
	}
	data, err := h.service.List(c.Request.Context(), dto.ListScheduledJobsQuery{Page: page, PageSize: pageSize, Keyword: strings.TrimSpace(c.Query("keyword"))})
	if err != nil {
		response.Fail(c, errcode.InternalServerError, "获取定时任务列表失败")
		return
	}
	response.Success(c, data)
}

func (h *scheduledJobHandler) Get(c *gin.Context) {
	id, ok := parseScheduledJobID(c)
	if !ok {
		return
	}
	data, err := h.service.Get(c.Request.Context(), id)
	if err != nil {
		handleScheduledJobError(c, err, "获取定时任务失败")
		return
	}
	response.Success(c, data)
}

func (h *scheduledJobHandler) Update(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可管理定时任务")
		return
	}
	id, ok := parseScheduledJobID(c)
	if !ok {
		return
	}
	var request dto.UpdateScheduledJobRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "请求体解析失败")
		return
	}
	data, err := h.service.Update(c.Request.Context(), id, request)
	if err != nil {
		handleScheduledJobError(c, err, "编辑定时任务失败")
		return
	}
	response.Success(c, data)
}

func (h *scheduledJobHandler) Delete(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可管理定时任务")
		return
	}
	id, ok := parseScheduledJobID(c)
	if !ok {
		return
	}
	if err := h.service.Delete(c.Request.Context(), id); err != nil {
		handleScheduledJobError(c, err, "删除定时任务失败")
		return
	}
	response.Success(c, gin.H{"id": id})
}

func (h *scheduledJobHandler) Trigger(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可触发定时任务")
		return
	}
	id, ok := parseScheduledJobID(c)
	if !ok {
		return
	}
	data, err := h.service.Trigger(c.Request.Context(), id, "manual")
	if err != nil {
		handleScheduledJobError(c, err, "立即触发定时任务失败")
		return
	}
	response.SuccessWithStatus(c, 202, data)
}

func (h *scheduledJobHandler) ListRuns(c *gin.Context) {
	id, ok := parseScheduledJobID(c)
	if !ok {
		return
	}
	page, pageSize, ok := parseScheduledJobPage(c)
	if !ok {
		return
	}
	data, err := h.service.ListRuns(c.Request.Context(), id, dto.ListScheduledJobRunsQuery{Page: page, PageSize: pageSize})
	if err != nil {
		handleScheduledJobError(c, err, "获取定时任务执行记录失败")
		return
	}
	response.Success(c, data)
}

func (h *scheduledJobHandler) GetRun(c *gin.Context) {
	runID, err := strconv.ParseInt(strings.TrimSpace(c.Param("run_id")), 10, 64)
	if err != nil || runID <= 0 {
		response.Fail(c, errcode.InvalidParams, "执行记录 id 不合法")
		return
	}
	data, serviceErr := h.service.GetRun(c.Request.Context(), runID)
	if serviceErr != nil {
		handleScheduledJobError(c, serviceErr, "获取定时任务执行记录失败")
		return
	}
	response.Success(c, data)
}

func parseScheduledJobID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id <= 0 {
		response.Fail(c, errcode.InvalidParams, "定时任务 id 不合法")
		return 0, false
	}
	return id, true
}
func parseScheduledJobPage(c *gin.Context) (int, int, bool) {
	page, err := parsePositiveIntQuery(c.Query("page"), 1)
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "page 参数必须是大于等于 1 的整数")
		return 0, 0, false
	}
	size, err := parsePositiveIntQuery(c.Query("page_size"), 10)
	if err != nil || size > 100 {
		response.Fail(c, errcode.InvalidParams, "page_size 参数必须在 1-100 之间")
		return 0, 0, false
	}
	return page, size, true
}
func handleScheduledJobError(c *gin.Context, err error, fallback string) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		response.Fail(c, errcode.NotFound, "定时任务不存在")
		return
	}
	if errors.Is(err, service.ErrInvalidScheduledJob) || errors.Is(err, service.ErrScheduledJobHandlerNotFound) {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}
	response.Fail(c, errcode.InternalServerError, fallback)
}
