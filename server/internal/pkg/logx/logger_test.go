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
	logger.Error("database write failed", "task_id", int64(42), "error", errors.New("INSERT INTO assets VALUES ('secret-response')"), "failure_reason", "扫描子进程退出异常: exit status 7")

	logged := output.String()
	if strings.Contains(logged, "secret-response") || strings.Contains(logged, "INSERT INTO") {
		t.Fatalf("error details leaked into log: %s", logged)
	}
	if !strings.Contains(logged, `"task_id":42`) || !strings.Contains(logged, `"error":"details hidden"`) {
		t.Fatalf("missing safe log fields: %s", logged)
	}
	if !strings.Contains(logged, `"failure_reason":"扫描子进程退出异常: exit status 7"`) {
		t.Fatalf("missing failure reason: %s", logged)
	}
}

func TestLoggerPreservesScannerDiagnostic(t *testing.T) {
	var output bytes.Buffer
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&output), zapcore.InfoLevel)
	logger := &Logger{raw: zap.New(core)}
	logger.Error("scan task scanner error", "task_id", int64(550), "event_type", "stderr", "diagnostic", "[FTL] no templates provided for scan")
	if logged := output.String(); !strings.Contains(logged, `"diagnostic":"[FTL] no templates provided for scan"`) || !strings.Contains(logged, `"task_id":550`) {
		t.Fatalf("missing scanner diagnostic: %s", logged)
	}
}
