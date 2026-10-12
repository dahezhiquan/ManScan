package handler

import (
	"errors"
	"strings"

	"ManScan/server/internal/middleware"
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/auth"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

type AuthHandler interface {
	Challenge(c *gin.Context)
	Login(c *gin.Context)
	Logout(c *gin.Context)
	Me(c *gin.Context)
	ListUsers(c *gin.Context)
	CreateUser(c *gin.Context)
}

type authHandler struct {
	service service.AuthService
}

func NewAuthHandler(authService service.AuthService) AuthHandler {
	return &authHandler{service: authService}
}

func (h *authHandler) Challenge(c *gin.Context) {
	data, serviceErr := h.service.Challenge(c.Request.Context(), c.ClientIP())
	if serviceErr != nil {
		handleAuthError(c, serviceErr, "生成验证码失败")
		return
	}
	response.Success(c, data)
}

func (h *authHandler) Login(c *gin.Context) {
	var request dto.LoginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "用户名、密码和验证码不能为空")
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

func (h *authHandler) ListUsers(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可查看用户列表")
		return
	}

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

	data, serviceErr := h.service.ListUsers(c.Request.Context(), dto.ListUsersQuery{
		Page:     page,
		PageSize: pageSize,
	})
	if serviceErr != nil {
		handleAuthError(c, serviceErr, "获取用户列表失败")
		return
	}
	response.Success(c, data)
}

func (h *authHandler) CreateUser(c *gin.Context) {
	if !isAdminRequest(c) {
		response.Fail(c, errcode.Forbidden, "仅管理员可新增用户")
		return
	}

	var request dto.CreateUserRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.Fail(c, errcode.InvalidParams, "username 和 password 不能为空")
		return
	}

	data, serviceErr := h.service.CreateUser(c.Request.Context(), request)
	if serviceErr != nil {
		handleAuthError(c, serviceErr, "新增用户失败")
		return
	}
	response.Success(c, data)
}

func isAdminRequest(c *gin.Context) bool {
	rawRole, ok := c.Get(middleware.ContextUserRoleKey)
	if !ok {
		return false
	}
	role, ok := rawRole.(string)
	return ok && strings.EqualFold(strings.TrimSpace(role), "admin")
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
	if errors.Is(err, service.ErrInvalidChallenge) {
		response.FailWithData(c, errcode.InvalidParams, service.ErrInvalidChallenge.Error(), dto.ChallengeFailureResponse{
			RefreshRequired: true,
		})
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
	if errors.Is(err, service.ErrInvalidUser) {
		response.Fail(c, errcode.InvalidParams, "username 和 password 不能为空，role 只能是 admin 或 user，status 只能是 enabled、disabled 或 locked")
		return
	}
	if errors.Is(err, service.ErrDuplicateUser) {
		response.Fail(c, errcode.InvalidParams, "username 已存在")
		return
	}
	if errors.Is(err, service.ErrUnauthorized) || errors.Is(err, auth.ErrInvalidToken) {
		response.Fail(c, errcode.Unauthorized, "登录状态已失效")
		return
	}
	response.Fail(c, errcode.InternalServerError, fallbackMessage)
}
