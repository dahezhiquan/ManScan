package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"ManScan/server/internal/middleware"
	"ManScan/server/internal/model/dto"

	"github.com/gin-gonic/gin"
)

func TestSettingHandlerUpdateThemeAcceptsFalseDarkMode(t *testing.T) {
	t.Parallel()

	svc := &settingServiceStub{}
	h := NewSettingHandler(svc)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(setTestUserID(7))
	router.PUT("/settings/theme", h.UpdateTheme)

	body := bytes.NewBufferString(`{"theme":"cartoon","dark_mode_enabled":false}`)
	req := httptest.NewRequest(http.MethodPut, "/settings/theme", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if svc.lastUserID != 7 {
		t.Fatalf("user id = %d, want 7", svc.lastUserID)
	}
	if svc.lastRequest == nil || svc.lastRequest.DarkModeEnabled == nil || *svc.lastRequest.DarkModeEnabled {
		t.Fatalf("request = %+v, want dark_mode_enabled=false", svc.lastRequest)
	}
}

func TestSettingHandlerGetThemeRequiresLogin(t *testing.T) {
	t.Parallel()

	svc := &settingServiceStub{}
	h := NewSettingHandler(svc)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/settings/theme", h.GetTheme)

	req := httptest.NewRequest(http.MethodGet, "/settings/theme", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if svc.getCalled {
		t.Fatalf("GetTheme service should not be called without current user")
	}
}

func setTestUserID(userID int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(middleware.ContextUserIDKey, userID)
		c.Next()
	}
}

type settingServiceStub struct {
	getCalled   bool
	lastUserID  int64
	lastRequest *dto.UpdateThemeSettingRequest
}

func (s *settingServiceStub) GetTheme(_ context.Context, userID int64) (*dto.ThemeSettingResponse, error) {
	s.getCalled = true
	s.lastUserID = userID
	return &dto.ThemeSettingResponse{
		Theme:           "cartoon",
		DarkModeEnabled: false,
	}, nil
}

func (s *settingServiceStub) UpdateTheme(_ context.Context, userID int64, request dto.UpdateThemeSettingRequest) (*dto.ThemeSettingResponse, error) {
	s.lastUserID = userID
	copyRequest := request
	s.lastRequest = &copyRequest
	darkModeEnabled := false
	if request.DarkModeEnabled != nil {
		darkModeEnabled = *request.DarkModeEnabled
	}
	return &dto.ThemeSettingResponse{
		Theme:           request.Theme,
		DarkModeEnabled: darkModeEnabled,
	}, nil
}
