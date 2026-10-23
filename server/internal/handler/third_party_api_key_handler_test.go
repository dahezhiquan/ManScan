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

func TestThirdPartyAPIKeyHandlerCRUDAndEncryptedStorage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&entity.ThirdPartyAPIKey{}); err != nil {
		t.Fatal(err)
	}
	box, err := secretbox.New("a sufficiently long API key encryption secret")
	if err != nil {
		t.Fatal(err)
	}
	svc := service.NewThirdPartyAPIKeyService(repository.NewThirdPartyAPIKeyRepository(db), box)
	h := handler.NewThirdPartyAPIKeyHandler(svc, nil)
	router := gin.New()
	router.Use(setAPIKeyTestRole("admin"))
	router.GET("/keys", h.List)
	router.GET("/keys/:id", h.Get)
	router.GET("/keys/:id/plaintext", h.GetPlaintext)
	router.POST("/keys", h.Create)
	router.PUT("/keys/:id", h.Update)
	router.DELETE("/keys/:id", h.Delete)

	created := performAPIKeyRequest(t, router, http.MethodPost, "/keys", `{"key":"secret-provider-key","platform_url":"https://api.example.com","rate_limit_per_minute":60,"description":"provider"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create status = %d body=%s", created.Code, created.Body.String())
	}
	var item entity.ThirdPartyAPIKey
	if err := db.First(&item).Error; err != nil {
		t.Fatal(err)
	}
	if item.EncryptedKey == "secret-provider-key" {
		t.Fatal("database contains the plaintext API key")
	}
	assertAPIKeyResponseHidesSecrets(t, created.Body.String(), "secret-provider-key", item.EncryptedKey)

	get := performAPIKeyRequest(t, router, http.MethodGet, fmt.Sprintf("/keys/%d", item.ID), "")
	list := performAPIKeyRequest(t, router, http.MethodGet, "/keys?page=1&page_size=10", "")
	assertAPIKeyResponseHidesSecrets(t, get.Body.String(), "secret-provider-key", item.EncryptedKey)
	assertAPIKeyResponseHidesSecrets(t, list.Body.String(), "secret-provider-key", item.EncryptedKey)

	plaintext := performAPIKeyRequest(t, router, http.MethodGet, fmt.Sprintf("/keys/%d/plaintext", item.ID), "")
	if plaintext.Code != http.StatusOK {
		t.Fatalf("plaintext status = %d body=%s", plaintext.Code, plaintext.Body.String())
	}
	if plaintext.Header().Get("Cache-Control") != "no-store" || plaintext.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("plaintext response cache headers = Cache-Control:%q Pragma:%q", plaintext.Header().Get("Cache-Control"), plaintext.Header().Get("Pragma"))
	}
	var plaintextEnvelope struct {
		Code int `json:"code"`
		Data struct {
			Key string `json:"key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(plaintext.Body.Bytes(), &plaintextEnvelope); err != nil {
		t.Fatalf("plaintext response is not JSON: %v", err)
	}
	if plaintextEnvelope.Code != 0 || plaintextEnvelope.Data.Key != "secret-provider-key" {
		t.Fatalf("plaintext response = %s", plaintext.Body.String())
	}

	updated := performAPIKeyRequest(t, router, http.MethodPut, fmt.Sprintf("/keys/%d", item.ID), `{"key":"replacement-provider-key","platform_url":"https://api.example.com/v2","rate_limit_per_minute":30,"description":"updated"}`)
	if updated.Code != http.StatusOK {
		t.Fatalf("update status = %d body=%s", updated.Code, updated.Body.String())
	}
	if err := db.First(&item, item.ID).Error; err != nil {
		t.Fatal(err)
	}
	if decrypted, err := box.Decrypt(item.EncryptedKey); err != nil || decrypted != "replacement-provider-key" {
		t.Fatalf("updated stored key decrypt = %q, %v", decrypted, err)
	}
	assertAPIKeyResponseHidesSecrets(t, updated.Body.String(), "replacement-provider-key", item.EncryptedKey)

	deleted := performAPIKeyRequest(t, router, http.MethodDelete, fmt.Sprintf("/keys/%d", item.ID), "")
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", deleted.Code, deleted.Body.String())
	}
	if err := db.First(&item, item.ID).Error; err == nil {
		t.Fatal("deleted API key still exists")
	}
	for _, request := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/keys/1", "", http.StatusNotFound},
		{http.MethodDelete, "/keys/1", "", http.StatusNotFound},
		{http.MethodGet, "/keys/invalid", "", http.StatusBadRequest},
		{http.MethodGet, "/keys?page=0", "", http.StatusBadRequest},
		{http.MethodGet, "/keys?page_size=101", "", http.StatusBadRequest},
		{http.MethodPost, "/keys", `{`, http.StatusBadRequest},
		{http.MethodPost, "/keys", `{"key":"","platform_url":"https://api.example.com"}`, http.StatusBadRequest},
		{http.MethodPost, "/keys", `{"key":"   ","platform_url":"https://api.example.com"}`, http.StatusBadRequest},
		{http.MethodPost, "/keys", `{"key":"key","platform_url":"file:///etc/passwd"}`, http.StatusBadRequest},
		{http.MethodPost, "/keys", `{"key":"key","platform_url":"https://user:pass@api.example.com"}`, http.StatusBadRequest},
		{http.MethodPost, "/keys", `{"key":"key","platform_url":"https://api.example.com","rate_limit_per_minute":-1}`, http.StatusBadRequest},
		{http.MethodPost, "/keys", `{"key":"key","platform_url":"https://api.example.com","rate_limit_per_minute":4294967296}`, http.StatusBadRequest},
		{http.MethodPost, "/keys", `{"key":"` + strings.Repeat("k", 513) + `","platform_url":"https://api.example.com"}`, http.StatusBadRequest},
		{http.MethodPost, "/keys", `{"key":"key","platform_url":"https://api.example.com","description":"` + strings.Repeat("a", 17*1024) + `"}`, http.StatusBadRequest},
	} {
		response := performAPIKeyRequest(t, router, request.method, request.path, request.body)
		if response.Code != request.status {
			t.Fatalf("%s %s status = %d, want %d; response = %s", request.method, request.path, response.Code, request.status, response.Body.String())
		}
	}
}

func TestThirdPartyAPIKeyHandlerRequiresAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := handler.NewThirdPartyAPIKeyHandler(nil, nil)
	router := gin.New()
	router.Use(setAPIKeyTestRole("user"))
	router.GET("/keys", h.List)
	router.GET("/keys/:id", h.Get)
	router.GET("/keys/:id/plaintext", h.GetPlaintext)
	router.POST("/keys", h.Create)
	router.PUT("/keys/:id", h.Update)
	router.DELETE("/keys/:id", h.Delete)
	for _, request := range []struct{ method, path string }{
		{http.MethodGet, "/keys"},
		{http.MethodGet, "/keys/1"},
		{http.MethodGet, "/keys/1/plaintext"},
		{http.MethodPost, "/keys"},
		{http.MethodPut, "/keys/1"},
		{http.MethodDelete, "/keys/1"},
	} {
		response := performAPIKeyRequest(t, router, request.method, request.path, `{}`)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s status = %d, want 403", request.method, request.path, response.Code)
		}
	}
}

func setAPIKeyTestRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(middleware.ContextUserRoleKey, role)
		c.Set(middleware.ContextUserIDKey, int64(42))
		c.Next()
	}
}

func performAPIKeyRequest(t *testing.T, router http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func assertAPIKeyResponseHidesSecrets(t *testing.T, response, plaintext, ciphertext string) {
	t.Helper()
	if strings.Contains(response, plaintext) || strings.Contains(response, ciphertext) || strings.Contains(response, `"api_key"`) {
		t.Fatalf("response contains key material: %s", response)
	}
	var envelope struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal([]byte(response), &envelope); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if envelope.Code != 0 {
		t.Fatalf("response failed: %s", response)
	}
}
