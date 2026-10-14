package handler

import (
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

// DashboardHandler 定义主页仪表盘区块接口。
type DashboardHandler interface {
	GetOverview(c *gin.Context)
	GetAssetRisks(c *gin.Context)
	GetHostRankings(c *gin.Context)
	GetServiceFingerprints(c *gin.Context)
}

type dashboardHandler struct {
	service service.DashboardService
}

// NewDashboardHandler 创建主页仪表盘处理器。
func NewDashboardHandler(dashboardService service.DashboardService) DashboardHandler {
	return &dashboardHandler{service: dashboardService}
}

// GetOverview 返回仪表盘漏洞及端口概览。
func (dashboard *dashboardHandler) GetOverview(ctx *gin.Context) {
	data, err := dashboard.service.GetOverview(ctx.Request.Context())
	if err != nil {
		response.Fail(ctx, errcode.ServiceUnavailable, "获取仪表盘概览失败，请稍后重试")
		return
	}
	response.Success(ctx, data)
}

// GetAssetRisks 返回仪表盘资产风险统计。
func (dashboard *dashboardHandler) GetAssetRisks(ctx *gin.Context) {
	data, err := dashboard.service.GetAssetRisks(ctx.Request.Context())
	if err != nil {
		response.Fail(ctx, errcode.ServiceUnavailable, "获取资产风险统计失败，请稍后重试")
		return
	}
	response.Success(ctx, data)
}

// GetHostRankings 返回仪表盘主机排行榜。
func (dashboard *dashboardHandler) GetHostRankings(ctx *gin.Context) {
	data, err := dashboard.service.GetHostRankings(ctx.Request.Context())
	if err != nil {
		response.Fail(ctx, errcode.ServiceUnavailable, "获取主机排行榜失败，请稍后重试")
		return
	}
	response.Success(ctx, data)
}

// GetServiceFingerprints 返回仪表盘服务指纹排行榜。
func (dashboard *dashboardHandler) GetServiceFingerprints(ctx *gin.Context) {
	data, err := dashboard.service.GetServiceFingerprints(ctx.Request.Context())
	if err != nil {
		response.Fail(ctx, errcode.ServiceUnavailable, "获取服务指纹排行榜失败，请稍后重试")
		return
	}
	response.Success(ctx, data)
}
