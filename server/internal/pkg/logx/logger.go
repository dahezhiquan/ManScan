package logx

import (
	"go.uber.org/zap"
)

type Logger struct {
	raw *zap.Logger
}

func New() *Logger {
	logger, err := zap.NewProduction()
	if err != nil {
		logger = zap.NewNop()
	}
	return &Logger{raw: logger}
}

func (l *Logger) Info(message string, fields ...interface{}) {
	l.raw.Info(message, toZapFields(fields...)...)
}

func (l *Logger) Error(message string, fields ...interface{}) {
	l.raw.Error(message, toZapFields(fields...)...)
}

func toZapFields(fields ...interface{}) []zap.Field {
	if len(fields) == 0 {
		return nil
	}

	result := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i+1 < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok || key == "" {
			continue
		}
		result = append(result, zap.Any(key, fields[i+1]))
	}
	return result
}
