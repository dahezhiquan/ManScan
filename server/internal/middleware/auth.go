package middleware

import (
	"errors"

	"ManScan/server/internal/pkg/auth"
	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

const (
	ContextUserIDKey   = "user_id"
	ContextUsernameKey = "username"
	ContextUserRoleKey = "user_role"
	ContextTokenKey    = "access_token"
)

func JWTAuth(authService service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := auth.ExtractBearerToken(c.GetHeader("Authorization"))
		if !ok {
			response.Fail(c, errcode.Unauthorized, "请先登录")
			c.Abort()
			return
		}

		user, err := authService.Authenticate(c.Request.Context(), token)
		if err != nil {
			if errors.Is(err, service.ErrUnauthorized) {
				response.Fail(c, errcode.Unauthorized, "登录状态已失效")
				c.Abort()
				return
			}
			response.Fail(c, errcode.InternalServerError, "鉴权失败")
			c.Abort()
			return
		}

		c.Set(ContextUserIDKey, user.User.ID)
		c.Set(ContextUsernameKey, user.User.Username)
		c.Set(ContextUserRoleKey, user.User.Role)
		c.Set(ContextTokenKey, token)
		c.Next()
	}
}
