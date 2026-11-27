package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ManScan/server/internal/handler"
	"ManScan/server/internal/middleware"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestNotificationHandlerCRUDValidationAndAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
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
	if err = db.AutoMigrate(&entity.Notification{}); err != nil {
		t.Fatal(err)
	}
	h := handler.NewNotificationHandler(service.NewNotificationService(repository.NewNotificationRepository(db), nil, nil, nil), nil)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(middleware.ContextUserRoleKey, c.GetHeader("X-Test-Role"))
		c.Set(middleware.ContextUsernameKey, "operator")
		c.Next()
	})
	router.POST("/notifications", h.Create)
	router.GET("/notifications", h.List)
	router.GET("/notifications/styles", h.Styles)
	router.GET("/notifications/:id", h.Get)
	router.PUT("/notifications/:id", h.Update)
	router.DELETE("/notifications/:id", h.Delete)
	router.POST("/notifications/:id/test", h.Test)
	request := func(method, path, body, role string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Test-Role", role)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	body := `{"name":"scan","description":"  扫描发起通知策略 🐱  ","enabled":true,"webhook":"https://open.feishu.cn/open-apis/bot/v2/hook/00000000-0000-0000-0000-000000000000","style":"cat_orange"}`
	created := request("POST", "/notifications", body, "admin")
	if created.Code != 200 {
		t.Fatalf("create: %s", created.Body.String())
	}
	var result struct {
		Data struct {
			ID          int64
			Description string
		}
	}
	if err = json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/notifications/%d", result.Data.ID)
	if result.Data.Description != "扫描发起通知策略 🐱" {
		t.Fatalf("create description=%q", result.Data.Description)
	}
	for _, test := range []struct {
		name, body, want string
		status           int
	}{
		{"omitted", `{"name":"scan","enabled":true}`, "扫描发起通知策略 🐱", 200},
		{"null", `{"name":"scan","enabled":true,"description":null}`, "扫描发起通知策略 🐱", 200},
		{"maximum", fmt.Sprintf(`{"name":"scan","enabled":true,"description":%q}`, strings.Repeat("猫", 500)), strings.Repeat("猫", 500), 200},
		{"overlong", fmt.Sprintf(`{"name":"scan","enabled":true,"description":%q}`, strings.Repeat("猫", 501)), strings.Repeat("猫", 500), 400},
		{"invalid type", `{"name":"scan","enabled":true,"description":123}`, strings.Repeat("猫", 500), 400},
		{"clear", `{"name":"scan","enabled":true,"description":""}`, "", 200},
	} {
		t.Run("description "+test.name, func(t *testing.T) {
			w := request("PUT", path, test.body, "admin")
			if w.Code != test.status {
				t.Fatalf("update: %d %s", w.Code, w.Body.String())
			}
			for i, response := range []*httptest.ResponseRecorder{w, request("GET", path, "", "admin")} {
				if i == 0 && test.status != 200 {
					continue
				}
				if response.Code != 200 {
					t.Fatalf("description response: %d %s", response.Code, response.Body.String())
				}
				var value struct{ Data struct{ Description *string } }
				if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
					t.Fatal(err)
				}
				if value.Data.Description == nil || *value.Data.Description != test.want {
					t.Fatalf("description response: %s", response.Body.String())
				}
			}
			listed := request("GET", "/notifications", "", "admin")
			var list struct {
				Data struct {
					Items []struct{ Description *string }
				}
			}
			if listed.Code != 200 {
				t.Fatalf("list: %s", listed.Body.String())
			}
			if err := json.Unmarshal(listed.Body.Bytes(), &list); err != nil {
				t.Fatal(err)
			}
			if len(list.Data.Items) != 1 || list.Data.Items[0].Description == nil || *list.Data.Items[0].Description != test.want {
				t.Fatalf("list description: %s", listed.Body.String())
			}
		})
	}
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/notifications", "", 200}, {"GET", path, "", 200}, {"GET", "/notifications/styles", "", 200},
		{"PUT", path, `{"name":"disabled","enabled":false,"style":"cat_purple"}`, 200},
		{"POST", "/notifications", `{"name":"missing switch"}`, 400},
		{"GET", "/notifications?page_size=101", "", 400}, {"GET", "/notifications/no-id", "", 400},
		{"GET", "/notifications/99999", "", 404}, {"POST", path + "/test", "", 503},
	} {
		w := request(tc.method, tc.path, tc.body, "admin")
		if w.Code != tc.status {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "00000000-") {
			t.Fatal("webhook secret exposed")
		}
	}

	// Exercise DTO binding as well as service validation for every header color.
	for _, test := range []struct{ style, color string }{
		{"blue", "blue"}, {"orange", "orange"}, {"purple", "purple"}, {"red", "red"}, {"green", "green"}, {"yellow", "yellow"}, {"grey", "grey"},
		{"cat_blue", "blue"}, {"cat_orange", "orange"}, {"cat_purple", "purple"},
	} {
		changed := request("PUT", path, fmt.Sprintf("{\"name\":\"color-test\",\"enabled\":false,\"style\":\"%s\"}", test.style), "admin")
		if changed.Code != 200 {
			t.Fatalf("style %s rejected: %s", test.style, changed.Body.String())
		}
		var data struct{ Data struct{ Style string } }
		if err := json.Unmarshal(changed.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		if data.Data.Style != test.color {
			t.Fatalf("style=%s want %s", data.Data.Style, test.color)
		}
	}
	invalid := request("PUT", path, "{\"name\":\"invalid\",\"enabled\":false,\"style\":\"cat_red\"}", "admin")
	if invalid.Code != 400 {
		t.Fatalf("invalid color accepted: %s", invalid.Body.String())
	}
	for _, event := range []string{"scan_started", "high_severity_vulnerability"} {
		changed := request("PUT", path, fmt.Sprintf("{\"name\":\"event-test\",\"enabled\":false,\"event\":\"%s\",\"style\":\"cat_purple\"}", event), "admin")
		if changed.Code != 200 {
			t.Fatalf("event %s rejected: %s", event, changed.Body.String())
		}
		var data struct{ Data struct{ Event string } }
		if err := json.Unmarshal(changed.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		if data.Data.Event != event {
			t.Fatalf("event=%s want %s", data.Data.Event, event)
		}
	}
	styles := request("GET", "/notifications/styles", "", "admin")
	var options struct {
		Data struct{ Items []struct{ ID, Name string } }
	}
	if err := json.Unmarshal(styles.Body.Bytes(), &options); err != nil {
		t.Fatal(err)
	}
	if len(options.Data.Items) != 7 {
		t.Fatalf("style options=%d", len(options.Data.Items))
	}
	for _, item := range options.Data.Items {
		if strings.HasPrefix(item.ID, "cat_") || strings.Contains(item.Name, "猫") {
			t.Fatal("theme name exposed in color options")
		}
	}
	var stored entity.Notification
	if err = db.First(&stored, result.Data.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Enabled || stored.Style != "purple" {
		t.Fatal("switch/style not updated")
	}
	if stored.Webhook != "https://open.feishu.cn/open-apis/bot/v2/hook/00000000-0000-0000-0000-000000000000" {
		t.Fatal("webhook not stored as plaintext")
	}
	for _, role := range []string{"", "user"} {
		for _, tc := range []struct{ method, path string }{{"GET", "/notifications"}, {"GET", "/notifications/styles"}, {"GET", path}, {"POST", "/notifications"}, {"PUT", path}, {"DELETE", path}, {"POST", path + "/test"}} {
			if w := request(tc.method, tc.path, body, role); w.Code != http.StatusForbidden {
				t.Fatalf("unprivileged %s %s allowed", tc.method, tc.path)
			}
		}
	}
	if w := request("DELETE", path, "", "admin"); w.Code != 200 {
		t.Fatalf("delete: %s", w.Body.String())
	}
	if w := request("GET", path, "", "admin"); w.Code != 404 {
		t.Fatalf("get after delete: %s", w.Body.String())
	}
}
