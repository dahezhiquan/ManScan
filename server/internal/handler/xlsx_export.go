package handler

import (
	"io"
	"os"
	"time"

	"ManScan/server/internal/pkg/errcode"
	"ManScan/server/internal/pkg/response"

	"github.com/gin-gonic/gin"
)

func sendExportXLSX(c *gin.Context, filePrefix, failureMessage string, write func(io.Writer) error) {
	file, err := os.CreateTemp("", "manscan-export-*.xlsx")
	if err != nil {
		response.Fail(c, errcode.InternalServerError, failureMessage)
		return
	}
	defer func() {
		_ = os.Remove(file.Name())
	}()
	if err := write(file); err != nil {
		_ = file.Close()
		response.Fail(c, errcode.InternalServerError, failureMessage)
		return
	}
	if err := file.Close(); err != nil {
		response.Fail(c, errcode.InternalServerError, failureMessage)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.FileAttachment(file.Name(), filePrefix+"-"+time.Now().Format("20060102-150405")+".xlsx")
}
