package service

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/pkg/secretbox"
	"ManScan/server/internal/repository"
	"gorm.io/gorm"
)

const NotificationEventScanStarted = "scan_started"

var (
	ErrInvalidNotification   = errors.New("通知参数不合法")
	ErrNotificationDelivery  = errors.New("飞书通知发送失败，请检查机器人配置与服务日志")
	ErrNotificationQueueFull = errors.New("通知队列已满")
)

// ScanStartedNotification is an immutable snapshot of an accepted scan.
type ScanStartedNotification struct {
	// Title is supplied by the trigger node, independently of the card style.
	Title             string
	TaskID            int64
	TaskNo            string
	Name              string
	Initiator         string
	TargetCount       int
	Description       string
	UserAgent         string
	TemplateSelection dto.CreateScanTaskRequest
}

// ScanStartNotifier accepts scan events without blocking the scan engine.
type ScanStartNotifier interface {
	EnqueueScanStarted(ctx context.Context, event ScanStartedNotification) error
}

// NotificationService manages subscriptions and dispatches accepted scan events.
type NotificationService interface {
	ScanStartNotifier
	Create(ctx context.Context, request dto.SaveNotificationRequest) (*dto.NotificationResponse, error)
	Update(ctx context.Context, id int64, request dto.SaveNotificationRequest) (*dto.NotificationResponse, error)
	Get(ctx context.Context, id int64) (*dto.NotificationResponse, error)
	List(ctx context.Context, page, pageSize int) (*dto.PageResult[dto.NotificationResponse], error)
	Delete(ctx context.Context, id int64) error
	Styles(ctx context.Context) []dto.NotificationStyle
	Test(ctx context.Context, id int64, initiator string) error
	Run(ctx context.Context)
}

type notificationService struct {
	repository repository.NotificationRepository
	box        *secretbox.Box
	logger     *logx.Logger
	templates  repository.TemplateRepository
	sender     FeishuSender
	queue      chan ScanStartedNotification
}

// NewNotificationService reuses the existing secret box for webhook encryption.
func NewNotificationService(repo repository.NotificationRepository, box *secretbox.Box, templates repository.TemplateRepository, sender FeishuSender, logger *logx.Logger) NotificationService {
	return &notificationService{repository: repo, box: box, templates: templates, sender: sender, logger: logger, queue: make(chan ScanStartedNotification, 128)}
}

// Create validates and encrypts the webhook before inserting a subscription.
func (s *notificationService) Create(ctx context.Context, request dto.SaveNotificationRequest) (*dto.NotificationResponse, error) {
	item := &entity.Notification{}
	if err := s.applyRequest(item, request, true); err != nil {
		return nil, err
	}
	if err := s.repository.Create(ctx, item); err != nil {
		return nil, errors.New("保存通知配置失败")
	}
	result := notificationResponse(*item)
	return &result, nil
}

// Update replaces metadata while preserving an omitted webhook.
func (s *notificationService) Update(ctx context.Context, id int64, request dto.SaveNotificationRequest) (*dto.NotificationResponse, error) {
	if id <= 0 {
		return nil, ErrInvalidNotification
	}
	item, err := s.repository.FindByID(ctx, id)
	if err != nil {
		return nil, notificationReadError(err)
	}
	if err = s.applyRequest(item, request, false); err != nil {
		return nil, err
	}
	if err = s.repository.Update(ctx, item, request.Webhook != nil); err != nil {
		return nil, errors.New("保存通知配置失败")
	}
	return s.Get(ctx, id)
}

func (s *notificationService) applyRequest(item *entity.Notification, request dto.SaveNotificationRequest, create bool) error {
	name := strings.TrimSpace(request.Name)
	event := strings.TrimSpace(request.Event)
	style := normalizeNotificationStyle(strings.TrimSpace(request.Style))
	if event == "" {
		event = NotificationEventScanStarted
	}
	if style == "" {
		style = "blue"
	}
	if name == "" || utf8.RuneCountInString(name) > 100 || request.Enabled == nil || event != NotificationEventScanStarted || !validNotificationStyle(style) {
		return ErrInvalidNotification
	}
	if create && request.Webhook == nil {
		return ErrInvalidNotification
	}
	if request.Webhook != nil {
		webhook := strings.TrimSpace(*request.Webhook)
		if !validFeishuWebhook(webhook) {
			return ErrInvalidNotification
		}
		if s.box == nil {
			return errors.New("通知加密器未配置")
		}
		encrypted, err := s.box.Encrypt(webhook)
		if err != nil {
			return errors.New("通知地址加密失败")
		}
		item.EncryptedWebhook = encrypted
	}
	item.Name, item.Enabled, item.Event, item.Style = name, *request.Enabled, event, style
	return nil
}

// Get returns metadata with a fully masked webhook token.
func (s *notificationService) Get(ctx context.Context, id int64) (*dto.NotificationResponse, error) {
	if id <= 0 {
		return nil, ErrInvalidNotification
	}
	item, err := s.repository.FindByID(ctx, id)
	if err != nil {
		return nil, notificationReadError(err)
	}
	result := notificationResponse(*item)
	return &result, nil
}

// List returns a bounded page containing no webhook secrets.
func (s *notificationService) List(ctx context.Context, page, pageSize int) (*dto.PageResult[dto.NotificationResponse], error) {
	if page < 1 || page > 2147483647 || pageSize < 1 || pageSize > 100 {
		return nil, ErrInvalidNotification
	}
	result, err := s.repository.List(ctx, page, pageSize)
	if err != nil {
		return nil, errors.New("读取通知配置失败")
	}
	items := make([]dto.NotificationResponse, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, notificationResponse(item))
	}
	return &dto.PageResult[dto.NotificationResponse]{Page: result.Page, PageSize: result.PageSize, Total: result.Total, TotalPages: result.TotalPages, Items: items}, nil
}

// Delete removes a subscription without affecting scan tasks.
func (s *notificationService) Delete(ctx context.Context, id int64) error {
	if id <= 0 {
		return ErrInvalidNotification
	}
	count, err := s.repository.Delete(ctx, id)
	if err != nil {
		return errors.New("删除通知配置失败")
	}
	if count == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// Styles lists the supported header colors independently of event titles.
func (s *notificationService) Styles(ctx context.Context) []dto.NotificationStyle {
	return notificationStyles()
}

// Test explicitly sends a preview, even when automatic notifications are disabled.
func (s *notificationService) Test(ctx context.Context, id int64, initiator string) error {
	if id <= 0 {
		return ErrInvalidNotification
	}
	item, err := s.repository.FindByID(ctx, id)
	if err != nil {
		return notificationReadError(err)
	}
	event := ScanStartedNotification{Title: "通知测试", Name: "ManScan 猫咪通知测试", Initiator: initiator, TargetCount: 0, Description: "这是一条通知连通性测试，未发起真实扫描。", UserAgent: "未发起扫描"}
	return s.deliver(ctx, *item, event, "0（通知测试）")
}

// EnqueueScanStarted copies display fields and template selection criteria.
func (s *notificationService) EnqueueScanStarted(ctx context.Context, event ScanStartedNotification) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(event.Title) == "" {
		return ErrInvalidNotification
	}
	event.Title = cardText(event.Title, 160)
	event.Name = cardText(event.Name, 160)
	event.Initiator = cardText(event.Initiator, 100)
	event.Description = cardText(event.Description, 1200)
	event.UserAgent = cardText(event.UserAgent, 700)
	selection := event.TemplateSelection
	event.TemplateSelection = dto.CreateScanTaskRequest{
		AutomaticScan: selection.AutomaticScan, NewTemplates: selection.NewTemplates, ScreenshotCapture: selection.ScreenshotCapture,
		DAST: selection.DAST, EnableCodeTemplates: selection.EnableCodeTemplates, EnableFileTemplates: selection.EnableFileTemplates, EnableGlobalMatchersTemplates: selection.EnableGlobalMatchersTemplates,
		IncludeIDs: append([]string(nil), selection.IncludeIDs...), Tags: append([]string(nil), selection.Tags...),
		Severities: append([]string(nil), selection.Severities...), Protocols: append([]string(nil), selection.Protocols...),
	}
	select {
	case s.queue <- event:
		return nil
	default:
		return ErrNotificationQueueFull
	}
}

// Run processes a bounded in-memory queue; shutdown cancels network requests.
func (s *notificationService) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case event := <-s.queue:
			s.dispatch(ctx, event)
		}
	}
}

func (s *notificationService) dispatch(ctx context.Context, event ScanStartedNotification) {
	var afterID int64
	templateCount := ""
	for {
		if ctx.Err() != nil {
			return
		}
		queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		items, err := s.repository.FindEnabled(queryCtx, NotificationEventScanStarted, afterID, 100)
		cancel()
		if err != nil {
			s.logFailure(event.TaskID, 0, "read_configuration")
			return
		}
		if len(items) == 0 {
			return
		}
		if templateCount == "" {
			templateCount = s.templateCount(event.TemplateSelection)
		}
		for _, item := range items {
			if ctx.Err() != nil {
				return
			}
			afterID = item.ID
			// Recheck the switch so queued events respect configuration edits.
			queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			current, err := s.repository.FindByID(queryCtx, item.ID)
			cancel()
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			if err != nil {
				s.logFailure(event.TaskID, item.ID, "read_configuration")
				continue
			}
			if !current.Enabled || current.Event != NotificationEventScanStarted {
				continue
			}
			if err = s.deliver(ctx, *current, event, templateCount); err != nil {
				s.logFailure(event.TaskID, item.ID, "send_failed")
			} else if s.logger != nil {
				s.logger.Info("scan notification delivered", "task_id", event.TaskID, "notification_id", item.ID)
			}
		}
		if len(items) < 100 {
			return
		}
	}
}

func (s *notificationService) deliver(ctx context.Context, item entity.Notification, event ScanStartedNotification, templateCount string) error {
	if s.box == nil || s.sender == nil || !validNotificationStyle(item.Style) {
		return ErrNotificationDelivery
	}
	webhook, err := s.box.Decrypt(item.EncryptedWebhook)
	if err != nil {
		return ErrNotificationDelivery
	}
	payload, err := buildScanStartedCard(item.Style, event, templateCount, notificationSystemIPs())
	if err != nil {
		return ErrNotificationDelivery
	}
	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err = s.sender.Send(sendCtx, webhook, payload); err != nil {
		return ErrNotificationDelivery
	}
	return nil
}

func (s *notificationService) logFailure(taskID, notificationID int64, reason string) {
	if s.logger != nil {
		s.logger.Error("scan notification failed", "task_id", taskID, "notification_id", notificationID, "reason", reason)
	}
}

func notificationResponse(item entity.Notification) dto.NotificationResponse {
	return dto.NotificationResponse{ID: item.ID, Name: item.Name, Enabled: item.Enabled, Event: item.Event, Webhook: "https://open.feishu.cn/open-apis/bot/v2/hook/********", Style: normalizeNotificationStyle(item.Style), CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}

func notificationReadError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return gorm.ErrRecordNotFound
	}
	return errors.New("读取通知配置失败")
}
