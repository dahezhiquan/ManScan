package service

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"ManScan/server/internal/model/entity"
)

var ErrScheduledJobHandlerNotFound = errors.New("定时任务类型未注册")

// ProgressReporter 接收后台任务的阶段和进度更新。
type ProgressReporter interface {
	Report(ctx context.Context, current, total int64, phase, message string) error
}

// OutputReporter records a file produced by one execution.
type OutputReporter interface {
	SetOutputPath(ctx context.Context, path string) error
}

// JobHandler 是具体后台任务的扩展接口。
type JobHandler interface {
	Type() string
	Validate(config json.RawMessage) error
	Execute(ctx context.Context, job entity.ScheduledJob, run entity.ScheduledJobRun, progress ProgressReporter) error
}

type JobHandlerRegistry interface {
	Register(handler JobHandler) error
	Validate(jobType string, config json.RawMessage) error
	Get(jobType string) (JobHandler, error)
}

type jobHandlerRegistry struct {
	mu       sync.RWMutex
	handlers map[string]JobHandler
}

// NewJobHandlerRegistry 创建空的定时任务处理器注册表。
func NewJobHandlerRegistry() JobHandlerRegistry {
	return &jobHandlerRegistry{handlers: make(map[string]JobHandler)}
}

func (r *jobHandlerRegistry) Register(handler JobHandler) error {
	if handler == nil || handler.Type() == "" {
		return errors.New("定时任务处理器不能为空")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.handlers[handler.Type()]; exists {
		return errors.New("定时任务处理器已注册: " + handler.Type())
	}
	r.handlers[handler.Type()] = handler
	return nil
}

func (r *jobHandlerRegistry) Validate(jobType string, config json.RawMessage) error {
	handler, err := r.Get(jobType)
	if err != nil {
		return err
	}
	return handler.Validate(config)
}

func (r *jobHandlerRegistry) Get(jobType string) (JobHandler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	handler, ok := r.handlers[jobType]
	if !ok {
		return nil, ErrScheduledJobHandlerNotFound
	}
	return handler, nil
}
