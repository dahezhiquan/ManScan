package handler

import (
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

type AssetConfigCenterHandler interface {
	List(c *gin.Context)
}

type assetConfigCenterHandler struct {
	service service.AssetConfigCenterService
}

func NewAssetConfigCenterHandler(assetConfigCenterService service.AssetConfigCenterService) AssetConfigCenterHandler {
	return &assetConfigCenterHandler{service: assetConfigCenterService}
}

func (h *assetConfigCenterHandler) List(c *gin.Context) {
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

	query := dto.ListAssetConfigCentersQuery{
		Page:            page,
		PageSize:        pageSize,
		ItemNames:       parseMultiValueQuery(c, "item_name"),
		BigCategories:   parseMultiValueQuery(c, "big_category"),
		SmallCategories: parseMultiValueQuery(c, "small_category"),
		Statuses:        parseMultiValueQuery(c, "status"),
	}

	data, serviceErr := h.service.List(c.Request.Context(), query)
	if serviceErr != nil {
		response.Fail(c, errcode.InternalServerError, "获取资产配置中心列表失败")
		return
	}

	response.Success(c, data)
}
