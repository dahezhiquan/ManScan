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
	"ManScan/server/internal/pkg/secretbox"
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
	box, err := secretbox.New("notification-handler-test-secret-32-bytes")
	if err != nil {
		t.Fatal(err)
	}
	h := handler.NewNotificationHandler(service.NewNotificationService(repository.NewNotificationRepository(db), box, nil, nil, nil), nil)
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
	body := `{"name":"scan","enabled":true,"webhook":"https://open.feishu.cn/open-apis/bot/v2/hook/00000000-0000-0000-0000-000000000000","style":"cat_orange"}`
	created := request("POST", "/notifications", body, "admin")
	if created.Code != 200 {
		t.Fatalf("create: %s", created.Body.String())
	}
	var result struct{ Data struct{ ID int64 } }
	if err = json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/notifications/%d", result.Data.ID)
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
