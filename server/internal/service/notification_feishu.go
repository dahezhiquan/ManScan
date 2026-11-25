package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ManScan/server/internal/model/dto"
)

// FeishuSender sends pre-rendered cards to validated Feishu bot endpoints.
type FeishuSender interface {
	Send(ctx context.Context, webhook string, payload []byte) error
}
type feishuSender struct{ client *http.Client }

// NewFeishuSender restricts destinations, DNS results, redirects and response sizes.
func NewFeishuSender() FeishuSender {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialFeishu
	return &feishuSender{client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

var feishuWebhookPath = regexp.MustCompile("^/open-apis/bot/v2/hook/[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")

func validFeishuWebhook(raw string) bool {
	u, err := url.Parse(raw)
	return len(raw) <= 512 && err == nil && u.Scheme == "https" && u.Host == "open.feishu.cn" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawFragment == "" && u.Opaque == "" && u.RawPath == "" && feishuWebhookPath.MatchString(u.Path)
}

func publicFeishuIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	v4 := ip.To4()
	return v4 == nil || !(v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127)
}

func dialFeishu(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "open.feishu.cn" || port != "443" {
		return nil, ErrNotificationDelivery
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, ErrNotificationDelivery
	}
	for _, address := range addresses {
		if !publicFeishuIP(address.IP) {
			return nil, ErrNotificationDelivery
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	for _, address := range addresses {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, ErrNotificationDelivery
}

// Send accepts only a positive Feishu application-level acknowledgement.
func (s *feishuSender) Send(ctx context.Context, webhook string, payload []byte) (sendErr error) {
	if !validFeishuWebhook(webhook) || len(payload) > 20*1024 {
		return ErrNotificationDelivery
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(payload))
	if err != nil {
		return ErrNotificationDelivery
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response, err := s.client.Do(request)
	if err != nil {
		return ErrNotificationDelivery
	} // HTTP errors contain the secret URL.
	defer func() {
		if err := response.Body.Close(); err != nil && sendErr == nil {
			sendErr = ErrNotificationDelivery
		}
	}()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrNotificationDelivery
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		return ErrNotificationDelivery
	}
	var result struct {
		Code       *int
		StatusCode *int
	}
	if err = json.Unmarshal(body, &result); err != nil {
		return ErrNotificationDelivery
	}
	if result.Code == nil && result.StatusCode == nil {
		return ErrNotificationDelivery
	}
	if result.Code != nil && *result.Code != 0 {
		return ErrNotificationDelivery
	}
	if result.StatusCode != nil && *result.StatusCode != 0 {
		return ErrNotificationDelivery
	}
	return nil
}

// notificationStyles lists header colors independently of event titles.
func notificationStyles() []dto.NotificationStyle {
	return []dto.NotificationStyle{
		{ID: "blue", Name: "蓝色"},
		{ID: "orange", Name: "橙色"},
		{ID: "purple", Name: "紫色"},
		{ID: "red", Name: "红色"},
		{ID: "green", Name: "绿色"},
		{ID: "yellow", Name: "黄色"},
		{ID: "grey", Name: "灰色"},
	}
}

// normalizeNotificationStyle preserves compatibility with saved cat-themed IDs.
func normalizeNotificationStyle(style string) string {
	switch style {
	case "cat_blue":
		return "blue"
	case "cat_orange":
		return "orange"
	case "cat_purple":
		return "purple"
	default:
		return style
	}
}

func validNotificationStyle(style string) bool {
	color := normalizeNotificationStyle(style)
	for _, item := range notificationStyles() {
		if item.ID == color {
			return true
		}
	}
	return false
}

func cardText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "未填写"
	}
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return value
}

func buildScanStartedCard(style string, event ScanStartedNotification, templateCount, systemIPs string) ([]byte, error) {
	if !validNotificationStyle(style) {
		return nil, errors.New("不支持的通知样式")
	}
	color := normalizeNotificationStyle(style)
	if strings.TrimSpace(event.Title) == "" {
		return nil, errors.New("通知标题不能为空")
	}
	title := cardText(event.Title, 160)
	plain := func(value string) map[string]any { return map[string]any{"tag": "plain_text", "content": value} }
	field := func(label, value string) map[string]any {
		return map[string]any{"is_short": true, "text": plain(label + "\n" + value)}
	}
	elements := []any{
		map[string]any{"tag": "div", "text": plain("ฅ^•ﻌ•^ฅ  ManScan 安全巡逻中")},
		map[string]any{"tag": "div", "text": plain("📋 扫描任务\n" + cardText(event.Name, 160))},
		map[string]any{"tag": "div", "fields": []any{field("👤 发起人", cardText(event.Initiator, 100)), field("🎯 目标数量", strconv.Itoa(event.TargetCount)), field("🧩 模版数量", cardText(templateCount, 300)), field("🖥 当前系统 IP", cardText(systemIPs, 500))}},
		map[string]any{"tag": "hr"},
		map[string]any{"tag": "div", "text": plain("📝 扫描简介\n" + cardText(event.Description, 1200))},
		map[string]any{"tag": "div", "text": plain("🌐 扫描 UA\n" + cardText(event.UserAgent, 700))},
		map[string]any{"tag": "note", "elements": []any{plain("🐾 小猫已收到任务，正在认真巡逻 · " + cardText(event.TaskNo, 80))}},
	}
	payload := map[string]any{"msg_type": "interactive", "card": map[string]any{"config": map[string]any{"wide_screen_mode": true}, "header": map[string]any{"template": color, "title": plain(title)}, "elements": elements}}
	return json.Marshal(payload)
}

func notificationSystemIPs() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "获取失败"
	}
	seen := map[string]bool{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.IsGlobalUnicast() && !ip.IsLoopback() {
				seen[ip.String()] = true
			}
		}
	}
	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if len(ips) == 0 {
		return "未发现可用网卡 IP"
	}
	return strings.Join(ips, ", ")
}

func (s *notificationService) templateCount(request dto.CreateScanTaskRequest) string {
	if isScreenshotOnlyTask(request) {
		return "1（截图采集）"
	}
	if request.AutomaticScan {
		return "自动映射中（运行时确定）"
	}
	if request.NewTemplates {
		return "新模版筛选中（运行时确定）"
	}
	if s.templates == nil {
		return "待引擎加载"
	}
	items, err := s.templates.List()
	if err != nil {
		return "模版索引暂不可用（运行时确定）"
	}
	selectionValues := func(values []string) []string {
		result := make([]string, 0, len(values))
		for _, value := range values {
			for _, token := range strings.Split(value, ",") {
				if token = strings.TrimSpace(token); token != "" {
					result = append(result, token)
				}
			}
		}
		return result
	}
	ids := selectionValues(request.IncludeIDs)
	filtered := filterTemplateListItems(items, dto.ListTemplatesQuery{Tags: selectionValues(request.Tags), Severities: selectionValues(request.Severities), Protocols: selectionValues(request.Protocols)})
	count := len(filtered)
	if len(ids) > 0 {
		count = 0
		for _, item := range filtered {
			for _, pattern := range ids {
				matched, err := filepath.Match(strings.ToLower(strings.TrimSpace(pattern)), strings.ToLower(item.ID))
				if err == nil && matched {
					count++
					break
				}
			}
		}
	}
	return fmt.Sprintf("%d（配置候选数，以引擎实际加载为准）", count)
}
