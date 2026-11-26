package service

import (
	"context"
	"strings"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/scanruntime"
)

type scanInitiatorContextKey struct{}

// WithScanInitiator carries the authenticated user across the HTTP/service boundary.
func WithScanInitiator(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, scanInitiatorContextKey{}, strings.TrimSpace(username))
}

func scanInitiator(ctx context.Context, fallback string) string {
	if name, ok := ctx.Value(scanInitiatorContextKey{}).(string); ok && name != "" {
		return name
	}
	return fallback
}

func (s *scanTaskService) notifyScanStarted(ctx context.Context, task *entity.ScanTask, plan *normalizedTaskRequest, state *scanruntime.State) {
	if s.notifier == nil || !plan.Raw.NotifyOnStart {
		return
	}
	userAgent := assetDomainProbeUserAgent(plan.Raw.CustomHeaders)
	if userAgent == "" {
		userAgent = "引擎默认随机 UA（未指定固定 User-Agent）"
	}
	event := ScanStartedNotification{
		Title:  "扫描任务已发起",
		TaskID: task.ID, TaskNo: task.TaskNo, Name: task.Name, Initiator: scanInitiator(ctx, plan.CreatedBy),
		TargetCount: len(plan.CollectedTargets), Description: plan.Description, UserAgent: userAgent, TemplateSelection: plan.Raw,
	}
	// The task has been accepted; HTTP disconnects must not cancel its notification.
	if err := s.notifier.EnqueueScanStarted(context.WithoutCancel(ctx), event); err != nil {
		state.Append("warning", "notification_enqueue_failed", "扫描发起通知未入队，扫描继续执行")
		if s.logger != nil {
			s.logger.Error("scan notification enqueue failed", "task_id", task.ID)
		}
	}
}
