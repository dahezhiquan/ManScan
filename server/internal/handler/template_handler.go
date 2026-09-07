package handler

import (
	"strconv"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

type TemplateHandler interface {
	List(c *gin.Context)
	Detail(c *gin.Context)
	Tags(c *gin.Context)
	Protocols(c *gin.Context)
	Stats(c *gin.Context)
}

type templateHandler struct {
	service service.TemplateService
}

func NewTemplateHandler(templateService service.TemplateService) TemplateHandler {
	return &templateHandler{service: templateService}
}

func (h *templateHandler) List(c *gin.Context) {
	page := 1
	if rawPage := strings.TrimSpace(c.Query("page")); rawPage != "" {
		parsedPage, err := strconv.Atoi(rawPage)
		if err != nil || parsedPage < 1 {
			response.Fail(c, errcode.InvalidParams, "page 参数必须是大于等于 1 的整数")
			return
		}
		page = parsedPage
	}

	isKev, hasIsKev, err := parseOptionalBoolQuery(c.Query("iskev"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "iskev 参数必须是布尔值")
		return
	}

	isCVE, hasIsCVE, err := parseOptionalBoolQuery(c.Query("iscve"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "iscve 参数必须是布尔值")
		return
	}

	query := dto.ListTemplatesQuery{
		Page:       page,
		Names:      parseMultiValueQuery(c, "name"),
		Tags:       parseMultiValueQuery(c, "tag"),
		Severities: parseMultiValueQuery(c, "severity"),
		Protocols:  parseMultiValueQuery(c, "protocol"),
	}
	if hasIsKev {
		query.IsKEV = &isKev
	}
	if hasIsCVE {
		query.IsCVE = &isCVE
	}

	data, serviceErr := h.service.List(c.Request.Context(), query)
	if serviceErr != nil {
		response.Fail(c, errcode.InternalServerError, "获取模板列表失败")
		return
	}
	response.Success(c, data)
}

func (h *templateHandler) Detail(c *gin.Context) {
	templateID := strings.TrimSpace(c.Param("id"))
	if templateID == "" {
		response.Fail(c, errcode.InvalidParams, "模板 id 不能为空")
		return
	}

	data, err := h.service.Detail(c.Request.Context(), templateID)
	if err != nil {
		response.Fail(c, errcode.InternalServerError, "查询模板详情失败")
		return
	}
	if data == nil {
		response.Fail(c, errcode.NotFound, "未找到对应模板")
		return
	}

	response.Success(c, data)
}

func (h *templateHandler) Tags(c *gin.Context) {
	data, err := h.service.Tags(c.Request.Context())
	if err != nil {
		response.Fail(c, errcode.InternalServerError, "获取模板标签列表失败")
		return
	}
	response.Success(c, data)
}

func (h *templateHandler) Protocols(c *gin.Context) {
	data, err := h.service.Protocols(c.Request.Context())
	if err != nil {
		response.Fail(c, errcode.InternalServerError, "获取模板协议列表失败")
		return
	}
	response.Success(c, data)
}

func (h *templateHandler) Stats(c *gin.Context) {
	data, err := h.service.Stats(c.Request.Context())
	if err != nil {
		response.Fail(c, errcode.InternalServerError, "获取模板统计失败")
		return
	}
	response.Success(c, data)
}

func parseMultiValueQuery(c *gin.Context, key string) []string {
	result := make([]string, 0, len(c.QueryArray(key)))
	appendValue := func(value string) {
		for _, item := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(item)
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
	}

	for _, value := range c.QueryArray(key) {
		appendValue(value)
	}
	return result
}

func parseOptionalBoolQuery(value string) (bool, bool, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "":
		return false, false, nil
	case "1", "true", "yes", "y":
		return true, true, nil
	case "0", "false", "no", "n":
		return false, true, nil
	default:
		return false, true, strconv.ErrSyntax
	}
}
