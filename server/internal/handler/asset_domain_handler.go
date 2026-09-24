package handler

import (
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

type AssetDomainHandler interface {
	List(c *gin.Context)
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
