package service

import (
	"context"
	"errors"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/repository"
)

type scanNotifierStub struct {
	events []ScanStartedNotification
	err    error
}

func (s *scanNotifierStub) EnqueueScanStarted(ctx context.Context, event ScanStartedNotification) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.events = append(s.events, event)
	return s.err
}

func TestScanNotificationCreateRescanAndFailureIsolation(t *testing.T) {
	repo := &scanTaskRepositoryStub{}
	notifier := &scanNotifierStub{}
	svc := NewScanTaskService(repo, nil, nil, nil, nil, nil, nil, t.TempDir(), notifier).(*scanTaskService)
	launches := 0
	svc.taskRunner = func(taskID int64, plan *normalizedTaskRequest, runtime *scanTaskRuntime) { launches++ }
	ctx := WithScanInitiator(context.Background(), "authenticated-operator")
	request := dto.CreateScanTaskRequest{Name: "巡检", CreatedBy: "client-supplied-name", Description: "说明", Targets: []string{"https://example.com/", "https://example.com"}, InlineTargetsList: "https://other.example.com", CustomHeaders: []string{"User-Agent: first", "user-agent: ScanAgent/2.0"}, NotifyOnStart: true}
	result, err := svc.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(notifier.events) != 1 || launches != 1 {
		t.Fatal("create event or scan launch missing")
	}
	event := notifier.events[0]
	if event.Title != "扫描任务已发起" || event.TaskID != result.ID || event.TargetCount != 2 || event.Initiator != "authenticated-operator" || event.UserAgent != "ScanAgent/2.0" || event.Description != "说明" {
		t.Fatalf("bad scan event: %+v", event)
	}
	if _, err = svc.Rescan(WithScanInitiator(context.Background(), "rescan-operator"), result.ID); err != nil {
		t.Fatal(err)
	}
	if len(notifier.events) != 2 || notifier.events[1].Initiator != "rescan-operator" || notifier.events[1].TaskID == result.ID || notifier.events[1].Title != "扫描任务已发起" {
		t.Fatal("rescan event identity incorrect")
	}
	notifier.err = ErrNotificationQueueFull
	if _, err = svc.Create(ctx, request); err != nil {
		t.Fatal("notification failure blocked scan", err)
	}
	if launches != 3 {
		t.Fatal("scan not launched after notification failure")
	}
	if _, err = svc.Create(ctx, dto.CreateScanTaskRequest{Targets: []string{"https://silent.example.com"}}); err != nil {
		t.Fatal("create without notification failed", err)
	}
	if len(notifier.events) != 3 || launches != 4 {
		t.Fatal("notification was enqueued when notify_on_start was disabled")
	}
	repo.createErr = errors.New("db failed")
	if _, err = svc.Create(ctx, request); err == nil {
		t.Fatal("creation should fail")
	}
	if len(notifier.events) != 3 {
		t.Fatal("failed creation emitted event")
	}
	repo.createErr = nil
	if _, err = svc.Create(ctx, dto.CreateScanTaskRequest{}); err == nil {
		t.Fatal("invalid scan accepted")
	}
	if len(notifier.events) != 3 {
		t.Fatal("invalid scan emitted event")
	}
}

func TestNotificationTemplateCount(t *testing.T) {
	s := &notificationService{templates: &notificationTemplateRepositoryStub{items: []dto.TemplateListItem{
		{ID: "CVE-2026-A", Tags: []string{"web"}, Severity: "high", Protocols: []string{"http"}},
		{ID: "CVE-2026-B", Tags: []string{"web"}, Severity: "low", Protocols: []string{"http"}},
		{ID: "tcp-one", Tags: []string{"network"}, Severity: "high", Protocols: []string{"tcp"}},
	}}}
	for _, tc := range []struct {
		request dto.CreateScanTaskRequest
		want    string
	}{
		{dto.CreateScanTaskRequest{}, "3（配置候选数，以引擎实际加载为准）"},
		{dto.CreateScanTaskRequest{Tags: []string{"web"}, Severities: []string{"high"}}, "1（配置候选数，以引擎实际加载为准）"},
		{dto.CreateScanTaskRequest{IncludeIDs: []string{"cve-*"}}, "2（配置候选数，以引擎实际加载为准）"},
		{dto.CreateScanTaskRequest{AutomaticScan: true}, "自动映射中（运行时确定）"},
		{dto.CreateScanTaskRequest{NewTemplates: true}, "新模版筛选中（运行时确定）"},
		{dto.CreateScanTaskRequest{ScreenshotCapture: true}, "1（截图采集）"},
		{dto.CreateScanTaskRequest{ScreenshotCapture: true, EnableCodeTemplates: true}, "3（配置候选数，以引擎实际加载为准）"},
		{dto.CreateScanTaskRequest{IncludeIDs: []string{"cve-*,tcp-one"}}, "3（配置候选数，以引擎实际加载为准）"},
	} {
		if got := s.templateCount(tc.request); got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
}

type notificationTemplateRepositoryStub struct {
	repository.TemplateRepository
	items []dto.TemplateListItem
}

func (s *notificationTemplateRepositoryStub) List() ([]dto.TemplateListItem, error) {
	return s.items, nil
}
