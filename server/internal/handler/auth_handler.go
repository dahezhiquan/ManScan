package handler

import (
	"errors"

	"ManScan/server/internal/middleware"
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/auth"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

type AuthHandler interface {
	Login(c *gin.Context)
	Logout(c *gin.Context)
	Me(c *gin.Context)
}

type authHandler struct {
	service service.AuthService
}

func NewAuthHandler(authService service.AuthService) AuthHandler {
	return &authHandler{service: authService}
}

func (h *authHandler) Login(c *gin.Context) {
	var request dto.LoginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "用户名和密码不能为空")
		return
	}

	data, serviceErr := h.service.Login(c.Request.Context(), request, c.ClientIP(), c.GetHeader("User-Agent"))
	if serviceErr != nil {
		handleAuthError(c, serviceErr, "登录失败")
		return
	}
	response.Success(c, data)
}

func (h *authHandler) Logout(c *gin.Context) {
	rawToken, ok := c.Get(middleware.ContextTokenKey)
	if !ok {
		response.Fail(c, errcode.Unauthorized, "请先登录")
		return
	}
	token, ok := rawToken.(string)
	if !ok || token == "" {
		response.Fail(c, errcode.Unauthorized, "请先登录")
		return
	}

	data, serviceErr := h.service.Logout(c.Request.Context(), token)
	if serviceErr != nil {
		handleAuthError(c, serviceErr, "退出登录失败")
		return
	}
	response.Success(c, data)
}

func (h *authHandler) Me(c *gin.Context) {
	rawUserID, ok := c.Get(middleware.ContextUserIDKey)
	if !ok {
		response.Fail(c, errcode.Unauthorized, "请先登录")
		return
	}

	userID, ok := rawUserID.(int64)
	if !ok || userID <= 0 {
		response.Fail(c, errcode.Unauthorized, "登录状态已失效")
		return
	}

	data, serviceErr := h.service.CurrentUser(c.Request.Context(), userID)
	if serviceErr != nil {
		handleAuthError(c, serviceErr, "获取当前用户失败")
		return
	}
	response.Success(c, data)
}

func handleAuthError(c *gin.Context, err error, fallbackMessage string) {
	var loginFailedErr *service.LoginFailedError
	if errors.As(err, &loginFailedErr) {
		response.FailWithData(c, errcode.Unauthorized, loginFailedErr.Error(), dto.LoginFailureResponse{
			RemainingAttempts: loginFailedErr.RemainingAttempts,
			Locked:            loginFailedErr.Locked,
		})
		return
	}
	if errors.Is(err, service.ErrInvalidCredentials) {
		response.Fail(c, errcode.Unauthorized, "用户名或密码错误")
		return
	}
	if errors.Is(err, service.ErrUserLocked) {
		response.FailWithData(c, errcode.Forbidden, "账户已锁定", dto.LoginFailureResponse{
			RemainingAttempts: 0,
			Locked:            true,
		})
		return
	}
	if errors.Is(err, service.ErrUserDisabled) {
		response.Fail(c, errcode.Forbidden, "用户已被禁用")
		return
	}
	if errors.Is(err, service.ErrUnauthorized) || errors.Is(err, auth.ErrInvalidToken) {
		response.Fail(c, errcode.Unauthorized, "登录状态已失效")
		return
	}
	response.Fail(c, errcode.InternalServerError, fallbackMessage)
}
