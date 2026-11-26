package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const testNotificationWebhook = "https://open.feishu.cn/open-apis/bot/v2/hook/00000000-0000-0000-0000-000000000000"

type notificationSenderStub struct {
	payloads [][]byte
	webhooks []string
	fail     bool
}

func (s *notificationSenderStub) Send(ctx context.Context, webhook string, payload []byte) error {
	s.webhooks = append(s.webhooks, webhook)
	s.payloads = append(s.payloads, append([]byte(nil), payload...))
	if s.fail {
		return errors.New("delivery failed")
	}
	return nil
}

func newNotificationTestService(t *testing.T) (*notificationService, *gorm.DB, *notificationSenderStub) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := repository.NewNotificationRepository(db).Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	sender := &notificationSenderStub{}
	svc := NewNotificationService(repository.NewNotificationRepository(db), nil, sender, nil).(*notificationService)
	return svc, db, sender
}

func notificationTestRequest(enabled bool) dto.SaveNotificationRequest {
	webhook := testNotificationWebhook
	return dto.SaveNotificationRequest{Name: "扫描通知", Enabled: &enabled, Webhook: &webhook}
}

func TestNotificationCRUDPlaintextSwitchAndPagination(t *testing.T) {
	s, db, _ := newNotificationTestService(t)
	if !db.Migrator().HasColumn(&entity.Notification{}, "webhook") || db.Migrator().HasColumn(&entity.Notification{}, "encrypted_webhook") {
		t.Fatal("notification schema must use only the webhook column")
	}
	ctx := context.Background()
	created, err := s.Create(ctx, notificationTestRequest(true))
	if err != nil {
		t.Fatal(err)
	}
	if !created.Enabled || created.Style != "blue" || created.Event != NotificationEventScanStarted {
		t.Fatalf("unexpected metadata: %+v", created)
	}
	var stored entity.Notification
	if err := db.First(&stored, created.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Webhook != testNotificationWebhook {
		t.Fatal("webhook was not stored as plaintext")
	}
	originalWebhook := stored.Webhook
	request := notificationTestRequest(false)
	request.Webhook = nil
	request.Style = "cat_orange"
	updated, err := s.Update(ctx, created.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Enabled || updated.Style != "orange" {
		t.Fatalf("false switch was not saved: %+v", updated)
	}
	if err := db.First(&stored, created.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Webhook != originalWebhook {
		t.Fatal("omitted webhook changed stored address")
	}
	newWebhook := strings.Replace(testNotificationWebhook, "00000000-", "11111111-", 1)
	request.Webhook = &newWebhook
	if _, err = s.Update(ctx, created.ID, request); err != nil {
		t.Fatal(err)
	}
	if err := db.First(&stored, created.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Webhook != newWebhook {
		t.Fatal("replacement webhook not stored")
	}
	if _, err := s.Create(ctx, notificationTestRequest(true)); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(ctx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || page.TotalPages != 2 || len(page.Items) != 1 {
		t.Fatalf("pagination: %+v", page)
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), testNotificationWebhook) || strings.Contains(string(encoded), stored.Webhook) {
		t.Fatal("credentials exposed")
	}
	enabled, err := s.repository.FindEnabled(ctx, NotificationEventScanStarted, 0, 1)
	if err != nil || len(enabled) != 1 || enabled[0].ID == created.ID {
		t.Fatal("event switch filtering failed")
	}
	if err = s.Delete(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, created.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("Get after delete: %v", err)
	}
	if err = s.Delete(ctx, created.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("Delete missing: %v", err)
	}
}

func TestNotificationPlaintextWebhookDelivery(t *testing.T) {
	s, _, sender := newNotificationTestService(t)
	ctx := context.Background()
	created, err := s.Create(ctx, notificationTestRequest(true))
	if err != nil {
		t.Fatal(err)
	}
	item, err := s.repository.FindByID(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "opaque-ciphertext", "http://127.0.0.1/webhook"} {
		item.Webhook = invalid
		if err := s.repository.Update(ctx, item, true); err != nil {
			t.Fatal(err)
		}
		if err := s.Test(ctx, item.ID, "admin"); !errors.Is(err, ErrNotificationDelivery) {
			t.Fatal("invalid stored address accepted")
		}
	}
	if len(sender.webhooks) != 0 {
		t.Fatal("invalid stored address reached sender")
	}
	if _, err := s.Update(ctx, item.ID, notificationTestRequest(true)); err != nil {
		t.Fatal(err)
	}
	if err := s.Test(ctx, item.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(sender.webhooks) != 1 || sender.webhooks[0] != testNotificationWebhook {
		t.Fatal("plaintext address was not sent directly")
	}
}

func TestNotificationDescriptionLifecycle(t *testing.T) {
	s, db, _ := newNotificationTestService(t)
	ctx := context.Background()
	request := notificationTestRequest(true)
	description := "  扫描发起时通知安全巡检群 🐱  "
	request.Description = &description
	created, err := s.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	assertDescription := func(t *testing.T, want string) {
		t.Helper()
		got, err := s.Get(ctx, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		page, err := s.List(ctx, 1, 20)
		if err != nil {
			t.Fatal(err)
		}
		var stored entity.Notification
		if err := db.First(&stored, created.ID).Error; err != nil {
			t.Fatal(err)
		}
		if got.Description != want || stored.Description != want || len(page.Items) != 1 || page.Items[0].Description != want {
			t.Fatalf("description not preserved in storage/detail/list, want %q", want)
		}
	}
	if created.Description != strings.TrimSpace(description) {
		t.Fatalf("create description=%q", created.Description)
	}
	assertDescription(t, strings.TrimSpace(description))
	request.Webhook = nil
	maximum := strings.Repeat("猫", 500)
	empty, whitespace := "", " \n\t "
	for _, test := range []struct {
		name        string
		description *string
		want        string
	}{
		{"replace at character limit", &maximum, maximum},
		{"omitted preserves value", nil, maximum},
		{"explicit empty clears value", &empty, ""},
		{"restore value", &description, strings.TrimSpace(description)},
		{"whitespace clears value", &whitespace, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request.Description = test.description
			updated, err := s.Update(ctx, created.ID, request)
			if err != nil {
				t.Fatal(err)
			}
			if updated.Description != test.want {
				t.Fatalf("updated description=%q, want %q", updated.Description, test.want)
			}
			assertDescription(t, test.want)
		})
	}
	tooLong := strings.Repeat("猫", 501)
	request.Description = &tooLong
	if _, err := s.Update(ctx, created.ID, request); !errors.Is(err, ErrInvalidNotification) {
		t.Fatalf("overlong description accepted: %v", err)
	}
	assertDescription(t, "")
	legacy, err := s.Create(ctx, notificationTestRequest(false))
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Description != "" {
		t.Fatalf("omitted description=%q", legacy.Description)
	}
}

func TestNotificationDescriptionMigrationPreservesExistingPolicy(t *testing.T) {
	s, db, _ := newNotificationTestService(t)
	ctx := context.Background()
	created, err := s.Create(ctx, notificationTestRequest(true))
	if err != nil {
		t.Fatal(err)
	}
	var before entity.Notification
	if err := db.First(&before, created.ID).Error; err != nil {
		t.Fatal(err)
	}
	// Emulate an existing database created before the description field.
	if err := db.Migrator().DropColumn(&entity.Notification{}, "description"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.repository.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var after entity.Notification
	if err := db.First(&after, created.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("migration changed existing notification metadata or credentials")
	}
}

func TestNotificationInvalidConfiguration(t *testing.T) {
	s, _, _ := newNotificationTestService(t)
	cases := []func(*dto.SaveNotificationRequest){
		func(r *dto.SaveNotificationRequest) { r.Name = " " },
		func(r *dto.SaveNotificationRequest) { r.Name = strings.Repeat("猫", 101) },
		func(r *dto.SaveNotificationRequest) { value := strings.Repeat("猫", 501); r.Description = &value },
		func(r *dto.SaveNotificationRequest) { r.Enabled = nil },
		func(r *dto.SaveNotificationRequest) { r.Webhook = nil },
		func(r *dto.SaveNotificationRequest) { r.Style = "custom" },
		func(r *dto.SaveNotificationRequest) { r.Event = "scan_finished" },
		func(r *dto.SaveNotificationRequest) { bad := "http://127.0.0.1/"; r.Webhook = &bad },
	}
	for i, mutate := range cases {
		request := notificationTestRequest(true)
		mutate(&request)
		if _, err := s.Create(context.Background(), request); !errors.Is(err, ErrInvalidNotification) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	if _, err := s.List(context.Background(), 0, 100); !errors.Is(err, ErrInvalidNotification) {
		t.Fatal(err)
	}
	if _, err := s.List(context.Background(), 1, 101); !errors.Is(err, ErrInvalidNotification) {
		t.Fatal(err)
	}
}

func TestNotificationDispatchEnabledAndExplicitTest(t *testing.T) {
	s, _, sender := newNotificationTestService(t)
	ctx := context.Background()
	disabled, err := s.Create(ctx, notificationTestRequest(false))
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Create(ctx, notificationTestRequest(true))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Create(ctx, notificationTestRequest(true))
	if err != nil {
		t.Fatal(err)
	}
	event := ScanStartedNotification{Title: "扫描任务已发起", TaskID: 42, Name: "资产巡检", Initiator: "admin", TargetCount: 7, Description: "测试简介", UserAgent: "ManScan-Test/1.0"}
	if err := s.EnqueueScanStarted(ctx, event); err != nil {
		t.Fatal(err)
	}
	// A configuration disabled after enqueue must not receive the pending event.
	update := notificationTestRequest(false)
	update.Webhook = nil
	if _, err := s.Update(ctx, first.ID, update); err != nil {
		t.Fatal(err)
	}
	s.dispatch(ctx, <-s.queue)
	if len(sender.payloads) != 1 {
		t.Fatalf("delivered %d cards, want 1", len(sender.payloads))
	}
	for _, want := range []string{"资产巡检", "admin", "测试简介", "ManScan-Test/1.0", "目标数量", "模版数量", "当前系统 IP"} {
		if !strings.Contains(string(sender.payloads[0]), want) {
			t.Fatalf("missing %q", want)
		}
	}
	if err := s.Test(ctx, disabled.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(sender.payloads) != 2 {
		t.Fatal("explicit preview did not send")
	}
	var preview map[string]any
	if err := json.Unmarshal(sender.payloads[1], &preview); err != nil {
		t.Fatal(err)
	}
	previewHeader := preview["card"].(map[string]any)["header"].(map[string]any)
	if got := previewHeader["title"].(map[string]any)["content"]; got != "通知测试" {
		t.Fatalf("preview trigger title=%v", got)
	}

	sender.fail = true
	if err := s.Test(ctx, second.ID, "admin"); !errors.Is(err, ErrNotificationDelivery) {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, first.ID, notificationTestRequest(true)); err != nil {
		t.Fatal(err)
	}
	before := len(sender.payloads)
	s.dispatch(ctx, event)
	if len(sender.payloads)-before != 2 {
		t.Fatal("one delivery failure stopped subsequent subscriptions")
	}
}

func TestHighSeverityVulnerabilityNotificationDispatch(t *testing.T) {
	s, _, sender := newNotificationTestService(t)
	enabled := true
	webhook := testNotificationWebhook
	description := "新增高危漏洞时通知测试群"
	_, err := s.Create(context.Background(), dto.SaveNotificationRequest{
		Name: "严重漏洞预警", Description: &description, Enabled: &enabled,
		Event: NotificationEventHighSeverityVulnerability, Webhook: &webhook, Style: "red",
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "app.example.test:443"
	event := HighSeverityVulnerabilityNotification{
		TaskID: 17, TaskName: "nightly scan",
		Vulnerability: entity.Vulnerability{Severity: "critical", VulnerabilityName: "远程代码执行", TemplateID: "CVE-demo", AssetEndpoint: &endpoint, LastFoundAt: time.Date(2026, 11, 26, 1, 2, 3, 0, time.UTC)},
	}
	if err := s.EnqueueHighSeverityVulnerability(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	s.dispatchHighSeverityVulnerability(context.Background(), <-s.vulnerabilityQueue)
	if len(sender.payloads) != 1 {
		t.Fatalf("delivered %d cards, want one", len(sender.payloads))
	}
	for _, want := range []string{"新增CRITICAL 漏洞预警", "远程代码执行", "CVE-demo", "app.example.test:443", "nightly scan", "17"} {
		if !strings.Contains(string(sender.payloads[0]), want) {
			t.Fatalf("card missing %q: %s", want, sender.payloads[0])
		}
	}
	if strings.Contains(string(sender.payloads[0]), "request") || strings.Contains(string(sender.payloads[0]), "payload") {
		t.Fatalf("card unexpectedly includes request details: %s", sender.payloads[0])
	}
}

func TestNotificationQueueCopiesSelectionAndHasBound(t *testing.T) {
	s, _, _ := newNotificationTestService(t)
	event := ScanStartedNotification{Title: "触发节点标题", TemplateSelection: dto.CreateScanTaskRequest{IncludeIDs: []string{"one"}, InteractshToken: "must-not-be-queued"}}
	if err := s.EnqueueScanStarted(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	event.TemplateSelection.IncludeIDs[0] = "changed"
	snapshot := <-s.queue
	if snapshot.Title != "触发节点标题" || snapshot.TemplateSelection.IncludeIDs[0] != "one" || snapshot.TemplateSelection.InteractshToken != "" {
		t.Fatal("unsafe event snapshot")
	}
	for i := 0; i < cap(s.queue); i++ {
		if err := s.EnqueueScanStarted(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.EnqueueScanStarted(context.Background(), event); !errors.Is(err, ErrNotificationQueueFull) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.EnqueueScanStarted(ctx, event); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestNotificationFeishuURLAndIPValidation(t *testing.T) {
	if !validFeishuWebhook(testNotificationWebhook) {
		t.Fatal("valid webhook rejected")
	}
	for _, bad := range []string{
		strings.Replace(testNotificationWebhook, "https:", "http:", 1),
		strings.Replace(testNotificationWebhook, "open.feishu.cn", "open.feishu.cn.evil.test", 1),
		strings.Replace(testNotificationWebhook, "open.feishu.cn", "open.feishu.cn:443", 1),
		strings.Replace(testNotificationWebhook, "open.feishu.cn", "user@open.feishu.cn", 1),
		strings.Replace(testNotificationWebhook, "open.feishu.cn", "127.0.0.1", 1),
		strings.Replace(testNotificationWebhook, "/hook/", "/hook/%2e%2e/", 1),
		testNotificationWebhook + "?q=1", testNotificationWebhook + "?", testNotificationWebhook + "#fragment",
	} {
		if validFeishuWebhook(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.100.100.200", "::1", "fc00::1", "fe80::1", "0.0.0.0"} {
		if publicFeishuIP(net.ParseIP(ip)) {
			t.Fatalf("accepted nonpublic IP %s", ip)
		}
	}
	if !publicFeishuIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("public IP rejected")
	}
	sender := NewFeishuSender().(*feishuSender)
	if sender.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects enabled")
	}
	if _, err := dialFeishu(context.Background(), "tcp", "127.0.0.1:443"); err == nil {
		t.Fatal("arbitrary dial accepted")
	}
}

type notificationRoundTripper func(*http.Request) (*http.Response, error)

func (f notificationRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNotificationFeishuAcknowledgementAndErrorRedaction(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
		ok     bool
	}{
		{"{\"code\":0}", 200, true}, {"{\"StatusCode\":0}", 200, true}, {"{\"code\":1}", 200, false},
		{"{}", 200, false}, {"{\"code\":0,\"StatusCode\":1}", 200, false}, {"not-json", 200, false}, {"{\"code\":0}", 500, false},
		{strings.Repeat("x", 65537), 200, false},
	} {
		sender := NewFeishuSender().(*feishuSender)
		sender.client.Transport = notificationRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.Method != "POST" || !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
				t.Fatal("bad outgoing request")
			}
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header), Request: r}, nil
		})
		err := sender.Send(context.Background(), testNotificationWebhook, []byte("{}"))
		if (err == nil) != tc.ok {
			t.Fatalf("response status %d body length %d: %v", tc.status, len(tc.body), err)
		}
	}
	sender := NewFeishuSender().(*feishuSender)
	calls := 0
	sender.client.Transport = notificationRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{"http://127.0.0.1/"}}, Request: r}, nil
	})
	if err := sender.Send(context.Background(), testNotificationWebhook, []byte("{}")); err == nil || calls != 1 {
		t.Fatal("redirect followed")
	}
	sender.client.Transport = notificationRoundTripper(func(r *http.Request) (*http.Response, error) { return nil, errors.New(testNotificationWebhook) })
	if err := sender.Send(context.Background(), testNotificationWebhook, []byte("{}")); err == nil || strings.Contains(err.Error(), testNotificationWebhook) {
		t.Fatal("secret exposed in error")
	}
}

func TestNotificationCatCardPlainTextAndSize(t *testing.T) {
	for _, style := range []string{"blue", "orange", "purple", "red", "green", "yellow", "grey", "cat_blue", "cat_orange", "cat_purple"} {
		event := ScanStartedNotification{Title: "<at id=all>全员</at>" + strings.Repeat("猫", 10000), Name: "<at id=all>全员</at>", Description: strings.Repeat("猫", 10000), UserAgent: strings.Repeat("A", 10000), Initiator: "operator", TargetCount: 3}
		payload, err := buildScanStartedCard(style, event, "2", "192.168.0.2")
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) > 20*1024 {
			t.Fatalf("card too large: %d", len(payload))
		}
		var decoded map[string]any
		if err = json.Unmarshal(payload, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["msg_type"] != "interactive" || strings.Contains(string(payload), "lark_md") {
			t.Fatal("unsafe card rendering")
		}
	}
}

// TestNotificationFeishuLive only sends when a tester explicitly supplies a webhook.
func TestNotificationFeishuLive(t *testing.T) {
	webhook := os.Getenv("MANSCAN_TEST_FEISHU_WEBHOOK")
	if webhook == "" {
		t.Skip("explicit test webhook required")
	}
	event := ScanStartedNotification{Title: "通知联调测试", TaskNo: "notification-integration-test", Name: "ManScan 猫咪通知联调", Initiator: "用户授权测试", TargetCount: 0, Description: "这是一条猫咪通知联调消息，用于验证卡片字段和机器人连通性，未发起真实扫描。", UserAgent: "通知联调（无扫描请求）"}
	payload, err := buildScanStartedCard("cat_orange", event, "0（通知测试）", notificationSystemIPs())
	if err != nil {
		t.Fatal(err)
	}
	if err = NewFeishuSender().Send(context.Background(), webhook, payload); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationStylesOnlyChangeHeaderColor(t *testing.T) {
	svc, _, _ := newNotificationTestService(t)
	wantStyles := []dto.NotificationStyle{
		{ID: "blue", Name: "蓝色"}, {ID: "orange", Name: "橙色"}, {ID: "purple", Name: "紫色"},
		{ID: "red", Name: "红色"}, {ID: "green", Name: "绿色"}, {ID: "yellow", Name: "黄色"}, {ID: "grey", Name: "灰色"},
	}
	if got := svc.Styles(context.Background()); !reflect.DeepEqual(got, wantStyles) {
		t.Fatalf("styles=%+v, want %+v", got, wantStyles)
	}
	event := ScanStartedNotification{Title: "节点自定义标题", TaskNo: "test-task", Name: "示例扫描", Initiator: "tester", TargetCount: 3, Description: "说明", UserAgent: "Test/1.0"}
	var baseline map[string]any
	for _, test := range []struct{ style, color string }{
		{"blue", "blue"}, {"orange", "orange"}, {"purple", "purple"}, {"red", "red"}, {"green", "green"}, {"yellow", "yellow"}, {"grey", "grey"},
		{"cat_blue", "blue"}, {"cat_orange", "orange"}, {"cat_purple", "purple"},
	} {
		t.Run(test.style, func(t *testing.T) {
			payload, err := buildScanStartedCard(test.style, event, "2", "192.168.0.2")
			if err != nil {
				t.Fatal(err)
			}
			var card map[string]any
			if err = json.Unmarshal(payload, &card); err != nil {
				t.Fatal(err)
			}
			header := card["card"].(map[string]any)["header"].(map[string]any)
			if header["template"] != test.color {
				t.Fatalf("header color=%v, want %s", header["template"], test.color)
			}
			if title := header["title"].(map[string]any)["content"]; title != event.Title {
				t.Fatalf("unexpected title=%v", title)
			}
			delete(header, "template")
			if baseline == nil {
				baseline = card
			} else if !reflect.DeepEqual(card, baseline) {
				t.Fatal("style changed content outside the header color")
			}
		})
	}
	if _, err := buildScanStartedCard("custom", event, "2", "127.0.0.1"); err == nil {
		t.Fatal("unsupported color accepted")
	}
}

func TestNotificationStylesSaveNormalizeAndDeliverLegacy(t *testing.T) {
	svc, _, sender := newNotificationTestService(t)
	ctx := context.Background()
	for _, style := range []string{"blue", "orange", "purple", "red", "green", "yellow", "grey"} {
		request := notificationTestRequest(false)
		request.Style = style
		item, err := svc.Create(ctx, request)
		if err != nil {
			t.Fatalf("create %s: %v", style, err)
		}
		if item.Style != style {
			t.Fatalf("created style=%s, want %s", item.Style, style)
		}
		request.Webhook = nil
		if _, err = svc.Update(ctx, item.ID, request); err != nil {
			t.Fatalf("update %s: %v", style, err)
		}
	}
	for _, test := range []struct{ old, color string }{{"cat_blue", "blue"}, {"cat_orange", "orange"}, {"cat_purple", "purple"}} {
		request := notificationTestRequest(true)
		request.Style = test.old
		item, err := svc.Create(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := svc.repository.FindByID(ctx, item.ID)
		if err != nil {
			t.Fatal(err)
		}
		if item.Style != test.color || stored.Style != test.color {
			t.Fatalf("legacy input %s not normalized", test.old)
		}
		// Model a row already saved by the previous version without migrating it.
		stored.Style = test.old
		if err = svc.repository.Update(ctx, stored, false); err != nil {
			t.Fatal(err)
		}
		read, err := svc.Get(ctx, item.ID)
		if err != nil {
			t.Fatal(err)
		}
		if read.Style != test.color {
			t.Fatalf("legacy response style=%s", read.Style)
		}
		if err = svc.Test(ctx, item.ID, "tester"); err != nil {
			t.Fatalf("legacy preview: %v", err)
		}
		var payload map[string]any
		if err = json.Unmarshal(sender.payloads[len(sender.payloads)-1], &payload); err != nil {
			t.Fatal(err)
		}
		header := payload["card"].(map[string]any)["header"].(map[string]any)
		if header["template"] != test.color {
			t.Fatalf("legacy header color=%v", header["template"])
		}
	}
	page, err := svc.List(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if strings.HasPrefix(item.Style, "cat_") {
			t.Fatal("legacy theme exposed in list", item.Style)
		}
	}
}

func TestNotificationTitleComesFromTrigger(t *testing.T) {
	svc, _, _ := newNotificationTestService(t)
	for _, title := range []string{"扫描任务已发起", "通知测试", "另一个触发节点标题"} {
		event := ScanStartedNotification{Title: title, Name: "任务名称"}
		if err := svc.EnqueueScanStarted(context.Background(), event); err != nil {
			t.Fatal(err)
		}
		snapshot := <-svc.queue
		for _, style := range []string{"blue", "orange", "purple", "red", "green", "yellow", "grey"} {
			payload, err := buildScanStartedCard(style, snapshot, "0", "192.168.0.2")
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err = json.Unmarshal(payload, &decoded); err != nil {
				t.Fatal(err)
			}
			header := decoded["card"].(map[string]any)["header"].(map[string]any)
			if header["title"].(map[string]any)["content"] != title {
				t.Fatalf("style %s overwrote trigger title %q", style, title)
			}
		}
	}
	for _, title := range []string{"", "   "} {
		event := ScanStartedNotification{Title: title}
		if err := svc.EnqueueScanStarted(context.Background(), event); !errors.Is(err, ErrInvalidNotification) {
			t.Fatalf("empty title enqueue: %v", err)
		}
		if _, err := buildScanStartedCard("blue", event, "0", "192.168.0.2"); err == nil {
			t.Fatal("empty title rendered")
		}
	}
}
