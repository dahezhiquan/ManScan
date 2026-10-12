package handler

import (
	"errors"

	"ManScan/server/internal/middleware"
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

type SettingHandler interface {
	GetTheme(c *gin.Context)
	UpdateTheme(c *gin.Context)
}

type settingHandler struct {
	service service.SettingService
}

func NewSettingHandler(settingService service.SettingService) SettingHandler {
	return &settingHandler{service: settingService}
}

func (h *settingHandler) GetTheme(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		response.Fail(c, errcode.Unauthorized, "请先登录")
		return
	}

	data, serviceErr := h.service.GetTheme(c.Request.Context(), userID)
	if serviceErr != nil {
		handleSettingError(c, serviceErr, "获取主题设置失败")
		return
	}
	response.Success(c, data)
}

func (h *settingHandler) UpdateTheme(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		response.Fail(c, errcode.Unauthorized, "请先登录")
		return
	}

	var request dto.UpdateThemeSettingRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "请求体解析失败")
		return
	}

	data, serviceErr := h.service.UpdateTheme(c.Request.Context(), userID, request)
	if serviceErr != nil {
		handleSettingError(c, serviceErr, "保存主题设置失败")
		return
	}
	response.Success(c, data)
}

func currentUserID(c *gin.Context) (int64, bool) {
	rawUserID, ok := c.Get(middleware.ContextUserIDKey)
	if !ok {
		return 0, false
	}
	userID, ok := rawUserID.(int64)
	return userID, ok && userID > 0
}

func handleSettingError(c *gin.Context, err error, fallbackMessage string) {
	if errors.Is(err, service.ErrInvalidThemeSetting) {
		response.Fail(c, errcode.InvalidParams, "theme 必须是 1-32 位小写字母、数字、下划线或连字符，且以字母或数字开头")
		return
	}
	response.Fail(c, errcode.InternalServerError, fallbackMessage)
}
