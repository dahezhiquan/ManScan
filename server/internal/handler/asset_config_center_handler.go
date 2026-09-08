package handler

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AssetConfigCenterHandler interface {
	Create(c *gin.Context)
	List(c *gin.Context)
	SmallCategoryOptions(c *gin.Context)
	Update(c *gin.Context)
	Delete(c *gin.Context)
}

type assetConfigCenterHandler struct {
	service service.AssetConfigCenterService
}

func NewAssetConfigCenterHandler(assetConfigCenterService service.AssetConfigCenterService) AssetConfigCenterHandler {
	return &assetConfigCenterHandler{service: assetConfigCenterService}
}

func (h *assetConfigCenterHandler) Create(c *gin.Context) {
	var request dto.CreateAssetConfigCenterRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "请求体解析失败")
		return
	}

	data, serviceErr := h.service.Create(c.Request.Context(), request)
	if serviceErr != nil {
		handleAssetConfigCenterError(c, serviceErr, "新增资产配置项失败")
		return
	}

	response.Success(c, data)
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

func (h *assetConfigCenterHandler) SmallCategoryOptions(c *gin.Context) {
	bigCategories := parseMultiValueQuery(c, "big_category")
	if len(bigCategories) == 0 {
		response.Fail(c, errcode.InvalidParams, "big_category 参数不能为空")
		return
	}

	data, serviceErr := h.service.SmallCategoryOptions(c.Request.Context(), dto.ListAssetConfigCenterSmallCategoryOptionsQuery{
		BigCategories: bigCategories,
	})
	if serviceErr != nil {
		response.Fail(c, errcode.InternalServerError, "获取资产配置中心小分类列表失败")
		return
	}

	response.Success(c, data)
}

func (h *assetConfigCenterHandler) Update(c *gin.Context) {
	itemID, err := parseAssetConfigCenterID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}

	var request dto.UpdateAssetConfigCenterRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "请求体解析失败")
		return
	}

	data, serviceErr := h.service.Update(c.Request.Context(), itemID, request)
	if serviceErr != nil {
		handleAssetConfigCenterError(c, serviceErr, "编辑资产配置项失败")
		return
	}

	response.Success(c, data)
}

func (h *assetConfigCenterHandler) Delete(c *gin.Context) {
	itemID, err := parseAssetConfigCenterID(c.Param("id"))
	if err != nil {
		response.Fail(c, errcode.InvalidParams, err.Error())
		return
	}

	data, serviceErr := h.service.Delete(c.Request.Context(), itemID)
	if serviceErr != nil {
		handleAssetConfigCenterError(c, serviceErr, "删除资产配置项失败")
		return
	}

	response.Success(c, data)
}

func parseAssetConfigCenterID(raw string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("资产配置项 id 不合法")
	}
	return value, nil
}

func handleAssetConfigCenterError(c *gin.Context, err error, fallbackMessage string) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		response.Fail(c, errcode.NotFound, "资产配置项不存在")
		return
	}
	if errors.Is(err, service.ErrInvalidAssetConfigCenter) {
		response.Fail(c, errcode.InvalidParams, "item_name、big_category、small_category 不能为空，status 只能是 enabled 或 disabled")
		return
	}
	if errors.Is(err, service.ErrDuplicateAssetConfigCenterItemName) {
		response.Fail(c, errcode.InvalidParams, "item_name 已存在")
		return
	}
	response.Fail(c, errcode.InternalServerError, fallbackMessage)
}
