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

type AssetHostHandler interface {
	List(c *gin.Context)
	Detail(c *gin.Context)
}

type assetHostHandler struct {
	service service.AssetHostService
}

func NewAssetHostHandler(assetHostService service.AssetHostService) AssetHostHandler {
	return &assetHostHandler{service: assetHostService}
}

func (h *assetHostHandler) List(c *gin.Context) {
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
	hasPort, hasHasPort, err := parseOptionalBoolQuery(c.Query("has_port"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "has_port 参数必须是布尔值")
		return
	}

	query := dto.ListAssetHostsQuery{
		Page:         page,
		PageSize:     pageSize,
		Keyword:      c.Query("keyword"),
		Owner:        c.Query("owner"),
		OSType:       c.Query("os_type"),
		Region:       c.Query("region"),
		AssetAddress: c.Query("asset_address"),
		RiskLevels:   parseMultiValueQuery(c, "risk_level"),
	}
	if hasHasVulnerability {
		query.HasVulnerability = &hasVulnerability
	}
	if hasHasPort {
		query.HasPort = &hasPort
	}
	if hasIsAlive {
		query.IsAlive = &isAlive
	}

	data, serviceErr := h.service.List(c.Request.Context(), query)
	if serviceErr != nil {
		response.Fail(c, errcode.InternalServerError, "获取主机资产清单失败")
		return
	}

	response.Success(c, data)
}

func (h *assetHostHandler) Detail(c *gin.Context) {
	ipAddress := strings.TrimSpace(c.Query("ip_address"))
	if ipAddress == "" {
		ipAddress = strings.TrimSpace(c.Query("asset_address"))
	}
	if ipAddress == "" {
		response.Fail(c, errcode.InvalidParams, "ip_address 参数不能为空")
		return
	}

	data, serviceErr := h.service.Detail(c.Request.Context(), ipAddress)
	if serviceErr != nil {
		if errors.Is(serviceErr, gorm.ErrRecordNotFound) {
			response.Fail(c, errcode.NotFound, "主机资产不存在")
			return
		}
		response.Fail(c, errcode.InternalServerError, "获取主机资产详情失败")
		return
	}

	response.Success(c, data)
}
