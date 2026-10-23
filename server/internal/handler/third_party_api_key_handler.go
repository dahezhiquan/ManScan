package handler

import (
	"errors"
	"fmt"
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

type ThirdPartyAPIKeyHandler interface {
	Create(*gin.Context)
	List(*gin.Context)
	Get(*gin.Context)
	Update(*gin.Context)
	Delete(*gin.Context)
}

type thirdPartyAPIKeyHandler struct {
	service service.ThirdPartyAPIKeyService
	logger  *logx.Logger
}

// NewThirdPartyAPIKeyHandler 创建第三方 API Key 控制器。
func NewThirdPartyAPIKeyHandler(svc service.ThirdPartyAPIKeyService, logger *logx.Logger) ThirdPartyAPIKeyHandler {
	return &thirdPartyAPIKeyHandler{service: svc, logger: logger}
}

// Create 校验并创建第三方 API Key 配置。
func (h *thirdPartyAPIKeyHandler) Create(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可新增第三方 API Key")
		return
	}
	var request dto.CreateThirdPartyAPIKeyRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "请求体解析失败")
		return
	}
	data, err := h.service.Create(c.Request.Context(), request)
	if err != nil {
		handleThirdPartyAPIKeyError(c, err, "新增第三方 API Key 失败")
		return
	}
	h.logMutation(c, "create", data.ID)
	response.Success(c, data)
}

// List 分页查询第三方 API Key 元信息。
func (h *thirdPartyAPIKeyHandler) List(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可查看第三方 API Key")
		return
	}
	page, err := parsePositiveIntQuery(c.Query("page"), 1)
	if err != nil || page > 2147483647 {
		response.Fail(c, errcode.InvalidParams, "page 参数必须在 1-2147483647 之间")
		return
	}
	pageSize, err := parsePositiveIntQuery(c.Query("page_size"), 10)
	if err != nil || pageSize > 100 {
		response.Fail(c, errcode.InvalidParams, "page_size 参数必须在 1-100 之间")
		return
	}
	data, serviceErr := h.service.List(c.Request.Context(), dto.ListThirdPartyAPIKeysQuery{Page: page, PageSize: pageSize})
	if serviceErr != nil {
		response.Fail(c, errcode.InternalServerError, "获取第三方 API Key 列表失败")
		return
	}
	response.Success(c, data)
}

// Update 校验并更新第三方 API Key 配置。
func (h *thirdPartyAPIKeyHandler) Update(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可编辑第三方 API Key")
		return
	}
	id, err := parseThirdPartyAPIKeyID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}
	var request dto.UpdateThirdPartyAPIKeyRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "请求体解析失败")
		return
	}
	data, serviceErr := h.service.Update(c.Request.Context(), id, request)
	if serviceErr != nil {
		handleThirdPartyAPIKeyError(c, serviceErr, "编辑第三方 API Key 失败")
		return
	}
	h.logMutation(c, "update", data.ID)
	response.Success(c, data)
}

// Delete 删除第三方 API Key 配置。
func (h *thirdPartyAPIKeyHandler) Delete(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可删除第三方 API Key")
		return
	}
	id, err := parseThirdPartyAPIKeyID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}
	data, serviceErr := h.service.Delete(c.Request.Context(), id)
	if serviceErr != nil {
		handleThirdPartyAPIKeyError(c, serviceErr, "删除第三方 API Key 失败")
		return
	}
	h.logMutation(c, "delete", data.ID)
	response.Success(c, data)
}

func (h *thirdPartyAPIKeyHandler) logMutation(c *gin.Context, action string, id int64) {
	if h.logger != nil {
		h.logger.Info("third-party API key configuration changed", "action", action, "id", id, "user_id", c.GetInt64(middleware.ContextUserIDKey))
	}
}

func parseThirdPartyAPIKeyID(raw string) (int64, error) {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("第三方 API Key id 不合法")
	}
	return value, nil
}

// Get 返回指定 API Key 的配置元信息。
func (h *thirdPartyAPIKeyHandler) Get(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可查看第三方 API Key")
		return
	}
	id, err := parseThirdPartyAPIKeyID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}
	data, serviceErr := h.service.Get(c.Request.Context(), id)
	if serviceErr != nil {
		handleThirdPartyAPIKeyError(c, serviceErr, "获取第三方 API Key 失败")
		return
	}
	response.Success(c, data)
}

func handleThirdPartyAPIKeyError(c *gin.Context, err error, fallback string) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		response.Fail(c, errcode.NotFound, "第三方 API Key 不存在")
		return
	}
	if errors.Is(err, service.ErrInvalidThirdPartyAPIKey) {
		response.Fail(c, errcode.InvalidParams, "key、platform_url、description 或限流参数不合法")
		return
	}
	response.Fail(c, errcode.InternalServerError, fallback)
}
