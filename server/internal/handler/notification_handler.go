package handler

import (
	"errors"
	"net/http"
	"strconv"

	"ManScan/server/internal/middleware"
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// NotificationHandler exposes administrator-only notification management.
type NotificationHandler interface {
	Create(*gin.Context)
	Update(*gin.Context)
	Get(*gin.Context)
	List(*gin.Context)
	Delete(*gin.Context)
	Styles(*gin.Context)
	Test(*gin.Context)
}
type notificationHandler struct {
	service service.NotificationService
	logger  *logx.Logger
}

// NewNotificationHandler creates a notification controller.
func NewNotificationHandler(svc service.NotificationService, logger *logx.Logger) NotificationHandler {
	return &notificationHandler{service: svc, logger: logger}
}

func authorizeNotification(c *gin.Context) bool {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可管理通知配置")
		return false
	}
	return true
}

// Create binds and validates a new notification configuration.
func (h *notificationHandler) Create(c *gin.Context) {
	if !authorizeNotification(c) {
		return
	}
	var request dto.SaveNotificationRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "通知参数不合法")
		return
	}
	data, err := h.service.Create(c.Request.Context(), request)
	if err != nil {
		handleNotificationError(c, err)
		return
	}
	h.logMutation(c, "create", data.ID)
	response.Success(c, data)
}

// Update replaces the metadata and optionally replaces the webhook.
func (h *notificationHandler) Update(c *gin.Context) {
	if !authorizeNotification(c) {
		return
	}
	id, ok := notificationID(c)
	if !ok {
		return
	}
	var request dto.SaveNotificationRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "通知参数不合法")
		return
	}
	data, err := h.service.Update(c.Request.Context(), id, request)
	if err != nil {
		handleNotificationError(c, err)
		return
	}
	h.logMutation(c, "update", id)
	response.Success(c, data)
}

// Get returns one masked configuration.
func (h *notificationHandler) Get(c *gin.Context) {
	if !authorizeNotification(c) {
		return
	}
	id, ok := notificationID(c)
	if !ok {
		return
	}
	data, err := h.service.Get(c.Request.Context(), id)
	if err != nil {
		handleNotificationError(c, err)
		return
	}
	response.Success(c, data)
}

// List returns paginated masked configurations.
func (h *notificationHandler) List(c *gin.Context) {
	if !authorizeNotification(c) {
		return
	}
	page, err := parsePositiveIntQuery(c.Query("page"), 1)
	if err != nil || page > 2147483647 {
		response.Fail(c, errcode.InvalidParams, "page 参数必须在 1-2147483647 之间")
		return
	}
	size, err := parsePositiveIntQuery(c.Query("page_size"), 20)
	if err != nil || size > 100 {
		response.Fail(c, errcode.InvalidParams, "page_size 参数必须在 1-100 之间")
		return
	}
	data, err := h.service.List(c.Request.Context(), page, size)
	if err != nil {
		handleNotificationError(c, err)
		return
	}
	response.Success(c, data)
}

// Delete removes a configuration.
func (h *notificationHandler) Delete(c *gin.Context) {
	if !authorizeNotification(c) {
		return
	}
	id, ok := notificationID(c)
	if !ok {
		return
	}
	if err := h.service.Delete(c.Request.Context(), id); err != nil {
		handleNotificationError(c, err)
		return
	}
	h.logMutation(c, "delete", id)
	response.Success(c, gin.H{"id": id, "deleted_count": 1})
}

// Styles returns the supported cat card presets.
func (h *notificationHandler) Styles(c *gin.Context) {
	if !authorizeNotification(c) {
		return
	}
	response.Success(c, gin.H{"items": h.service.Styles(c.Request.Context())})
}

// Test explicitly sends a preview to the configured Feishu group.
func (h *notificationHandler) Test(c *gin.Context) {
	if !authorizeNotification(c) {
		return
	}
	id, ok := notificationID(c)
	if !ok {
		return
	}
	if err := h.service.Test(c.Request.Context(), id, c.GetString(middleware.ContextUsernameKey)); err != nil {
		handleNotificationError(c, err)
		return
	}
	h.logMutation(c, "test", id)
	response.Success(c, gin.H{"id": id, "sent": true})
}

func notificationID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.Fail(c, errcode.InvalidParams, "id 必须为正整数")
		return 0, false
	}
	return id, true
}

func handleNotificationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidNotification):
		response.Fail(c, errcode.InvalidParams, "名称、开关、事件、飞书 webhook 或卡片样式不合法")
	case errors.Is(err, gorm.ErrRecordNotFound):
		response.Fail(c, errcode.NotFound, "通知配置不存在")
	case errors.Is(err, service.ErrNotificationDelivery):
		response.Fail(c, errcode.ServiceUnavailable, service.ErrNotificationDelivery.Error())
	default:
		response.Fail(c, errcode.InternalServerError, "通知配置操作失败")
	}
}

func (h *notificationHandler) logMutation(c *gin.Context, action string, id int64) {
	if h.logger != nil {
		h.logger.Info("notification configuration changed", "action", action, "id", id, "user_id", c.GetInt64(middleware.ContextUserIDKey))
	}
}
