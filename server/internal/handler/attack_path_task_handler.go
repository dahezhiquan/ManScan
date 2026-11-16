package handler

import (
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const maxAttackPathUploadBytes = 1 << 30

type AttackPathTaskHandler interface {
	Create(*gin.Context)
	Get(*gin.Context)
	Download(*gin.Context)
	Cancel(*gin.Context)
}

type attackPathTaskHandler struct{ service service.AttackPathTaskService }

// NewAttackPathTaskHandler creates the attack path task controller.
func NewAttackPathTaskHandler(svc service.AttackPathTaskService) AttackPathTaskHandler {
	return &attackPathTaskHandler{service: svc}
}

func (h *attackPathTaskHandler) Create(c *gin.Context) {
	ownerID, ok := attackPathOwnerID(c)
	if !ok {
		response.Fail(c, errcode.Unauthorized, "登录状态无效")
		return
	}
	if c.Request.ContentLength > maxAttackPathUploadBytes+(1<<20) {
		response.Fail(c, errcode.InvalidParams, "仅支持 1 GiB 以内的 TXT 文件")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAttackPathUploadBytes+(1<<20))
	reader, err := c.Request.MultipartReader()
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "请上传 TXT 文件")
		return
	}
	part, err := reader.NextPart()
	if err != nil {
		response.Fail(c, errcode.InvalidParams, "请上传 TXT 文件")
		return
	}
	defer part.Close()
	if part.FormName() != "file" || !strings.EqualFold(filepath.Ext(part.FileName()), ".txt") {
		response.Fail(c, errcode.InvalidParams, "仅支持 1 GiB 以内的 TXT 文件")
		return
	}
	task, err := h.service.Create(c.Request.Context(), ownerID, io.LimitReader(part, maxAttackPathUploadBytes+1))
	if err != nil {
		if errors.Is(err, service.ErrInvalidAttackPathInput) {
			response.Fail(c, errcode.InvalidParams, "TXT 内容为空或格式不合法；最多 500000 条路径，每条不超过 2048 字节")
			return
		}
		if errors.Is(err, service.ErrAttackPathUnavailable) {
			response.Fail(c, errcode.ServiceUnavailable, "攻击路径识别服务暂未配置")
			return
		}
		response.Fail(c, errcode.InternalServerError, "创建攻击路径识别任务失败")
		return
	}
	response.SuccessWithStatus(c, http.StatusAccepted, task)
}

func (h *attackPathTaskHandler) Get(c *gin.Context) {
	ownerID, ok := attackPathOwnerID(c)
	if !ok {
		response.Fail(c, errcode.Unauthorized, "登录状态无效")
		return
	}
	task, err := h.service.Get(c.Request.Context(), ownerID, c.Param("id"))
	if err != nil {
		attackPathTaskError(c, err)
		return
	}
	response.Success(c, task)
}

func (h *attackPathTaskHandler) Download(c *gin.Context) {
	ownerID, ok := attackPathOwnerID(c)
	if !ok {
		response.Fail(c, errcode.Unauthorized, "登录状态无效")
		return
	}
	content, size, err := h.service.Download(c.Request.Context(), ownerID, c.Param("id"))
	if err != nil {
		if errors.Is(err, service.ErrAttackPathNotReady) {
			response.Fail(c, errcode.ServiceUnavailable, "任务尚未完成或未生成结果")
			return
		}
		attackPathTaskError(c, err)
		return
	}
	filename := "normal-api-paths.txt"
	defer content.Close()
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=\""+filename+"\"")
	c.DataFromReader(http.StatusOK, size, "text/plain; charset=utf-8", content, nil)
}

func (h *attackPathTaskHandler) Cancel(c *gin.Context) {
	ownerID, ok := attackPathOwnerID(c)
	if !ok {
		response.Fail(c, errcode.Unauthorized, "登录状态无效")
		return
	}
	task, err := h.service.Cancel(c.Request.Context(), ownerID, c.Param("id"))
	if err != nil {
		attackPathTaskError(c, err)
		return
	}
	response.Success(c, task)
}

func attackPathOwnerID(c *gin.Context) (int64, bool) {
	value, ok := c.Get("user_id")
	if !ok {
		return 0, false
	}
	ownerID, ok := value.(int64)
	return ownerID, ok && ownerID > 0
}

func attackPathTaskError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		response.Fail(c, errcode.NotFound, "任务不存在")
		return
	}
	response.Fail(c, errcode.InternalServerError, "处理攻击路径任务失败")
}
