package handler

import (
	"errors"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AssetDomainHandler interface {
	List(c *gin.Context)
	Detail(c *gin.Context)
	UpdateManualNote(c *gin.Context)
	LatestScreenshot(c *gin.Context)
	ListScreenshots(c *gin.Context)
}

type assetDomainHandler struct {
	service service.AssetDomainService
}

func NewAssetDomainHandler(assetDomainService service.AssetDomainService) AssetDomainHandler {
	return &assetDomainHandler{service: assetDomainService}
}

func (h *assetDomainHandler) List(c *gin.Context) {
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
	isAlive, hasIsAlive, err := parseOptionalBoolQuery(c.Query("is_alive"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "is_alive 参数必须是布尔值")
		return
	}
	hasVulnerability, hasHasVulnerability, err := parseOptionalBoolQuery(c.Query("has_vulnerability"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "has_vulnerability 参数必须是布尔值")
		return
	}
	hasComponent, hasHasComponent, err := parseOptionalBoolQuery(c.Query("has_component"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "has_component 参数必须是布尔值")
		return
	}

	query := dto.ListAssetDomainsQuery{
		Page:         page,
		PageSize:     pageSize,
		Keyword:      c.Query("keyword"),
		Owner:        c.Query("owner"),
		Title:        c.Query("title"),
		Region:       c.Query("region"),
		AssetAddress: c.Query("asset_address"),
		RiskLevels:   parseMultiValueQuery(c, "risk_level"),
	}
	if hasHasVulnerability {
		query.HasVulnerability = &hasVulnerability
	}
	if hasHasComponent {
		query.HasComponent = &hasComponent
	}
	if hasIsAlive {
		query.IsAlive = &isAlive
	}

	data, serviceErr := h.service.List(c.Request.Context(), query)
	if serviceErr != nil {
		response.Fail(c, errcode.InternalServerError, "获取域名资产清单失败")
		return
	}

	response.Success(c, data)
}

func (h *assetDomainHandler) Detail(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	if domain == "" {
		response.Fail(c, errcode.InvalidParams, "domain 参数不能为空")
		return
	}

	data, serviceErr := h.service.Detail(c.Request.Context(), domain)
	if serviceErr != nil {
		if errors.Is(serviceErr, gorm.ErrRecordNotFound) {
			response.Fail(c, errcode.NotFound, "域名资产不存在")
			return
		}
		response.Fail(c, errcode.InternalServerError, "获取域名资产详情失败")
		return
	}

	response.Success(c, data)
}

func (h *assetDomainHandler) UpdateManualNote(c *gin.Context) {
	var request dto.UpdateAssetDomainManualNoteRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "请求体解析失败")
		return
	}

	data, serviceErr := h.service.UpdateManualNote(c.Request.Context(), request)
	if serviceErr != nil {
		if errors.Is(serviceErr, gorm.ErrRecordNotFound) {
			response.Fail(c, errcode.NotFound, "域名资产不存在")
			return
		}
		if errors.Is(serviceErr, service.ErrInvalidAssetDomain) {
			response.Fail(c, errcode.InvalidParams, "domain 参数不能为空")
			return
		}
		if errors.Is(serviceErr, service.ErrInvalidAssetManualNote) {
			response.Fail(c, errcode.InvalidParams, "manual_note 不能超过 5000 个字符")
			return
		}
		response.Fail(c, errcode.InternalServerError, "更新域名资产人工备注失败")
		return
	}

	response.Success(c, data)
}

// LatestScreenshot returns the newest screenshot for a domain asset.
func (h *assetDomainHandler) LatestScreenshot(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	if domain == "" {
		response.Fail(c, errcode.InvalidParams, "domain 参数不能为空")
		return
	}

	data, serviceErr := h.service.LatestScreenshot(c.Request.Context(), domain)
	if serviceErr != nil {
		switch {
		case errors.Is(serviceErr, service.ErrInvalidAssetDomain):
			response.Fail(c, errcode.InvalidParams, "domain 参数不合法")
		case errors.Is(serviceErr, service.ErrAssetDomainScreenshotNotFound):
			response.Fail(c, errcode.NotFound, "域名资产截图不存在")
		default:
			response.Fail(c, errcode.InternalServerError, "获取域名资产最新截图失败")
		}
		return
	}

	response.Success(c, data)
}

// ListScreenshots returns paginated screenshot history for a domain asset.
func (h *assetDomainHandler) ListScreenshots(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	if domain == "" {
		response.Fail(c, errcode.InvalidParams, "domain 参数不能为空")
		return
	}
	page, err := parsePositiveIntQuery(c.Query("page"), 1)
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "page 参数必须是大于等于 1 的整数")
		return
	}
	pageSize, err := parsePositiveIntQuery(c.Query("page_size"), 10)
	if err != nil || pageSize > 20 {
		response.Fail(c, errcode.InvalidParams, "page_size 参数必须在 1-20 之间")
		return
	}

	data, serviceErr := h.service.ListScreenshots(c.Request.Context(), dto.ListAssetDomainScreenshotsQuery{
		Domain: domain, Page: page, PageSize: pageSize,
	})
	if serviceErr != nil {
		if errors.Is(serviceErr, service.ErrInvalidAssetDomain) {
			response.Fail(c, errcode.InvalidParams, "domain 参数不合法")
			return
		}
		response.Fail(c, errcode.InternalServerError, "获取域名资产历史截图失败")
		return
	}

	response.Success(c, data)
}
