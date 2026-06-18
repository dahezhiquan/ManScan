package response

import (
	"net/http"

	"ManScan/server/internal/pkg/errcode"

	"github.com/gin-gonic/gin"
)

type Envelope struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Envelope{
		Code:    errcode.Success,
		Message: "success",
		Data:    data,
	})
}

func SuccessWithStatus(c *gin.Context, status int, data interface{}) {
	c.JSON(status, Envelope{
		Code:    errcode.Success,
		Message: "success",
		Data:    data,
	})
}

func Fail(c *gin.Context, code int, message string) {
	c.JSON(httpStatus(code), Envelope{
		Code:    code,
		Message: message,
		Data:    nil,
	})
}

func httpStatus(code int) int {
	switch code {
	case errcode.InvalidParams:
		return http.StatusBadRequest
	case errcode.NotFound:
		return http.StatusNotFound
	case errcode.ServiceUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
