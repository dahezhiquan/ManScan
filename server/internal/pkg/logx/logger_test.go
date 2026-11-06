package logx

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestLoggerHidesErrorDetails(t *testing.T) {
	var output bytes.Buffer
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&output), zapcore.InfoLevel)
	logger := &Logger{raw: zap.New(core)}
	logger.Error("database write failed", "task_id", int64(42), "error", errors.New("INSERT INTO assets VALUES ('secret-response')"))

	logged := output.String()
	if strings.Contains(logged, "secret-response") || strings.Contains(logged, "INSERT INTO") {
		t.Fatalf("error details leaked into log: %s", logged)
	}
	if !strings.Contains(logged, `"task_id":42`) || !strings.Contains(logged, `"error":"details hidden"`) {
		t.Fatalf("missing safe log fields: %s", logged)
	}
}
