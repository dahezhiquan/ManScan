package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"ManScan/server/internal/middleware"
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

func TestAuthHandlerListUsersRequiresAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stub := &authServiceStub{}
	handler := NewAuthHandler(stub)
	context, recorder := newAuthHandlerTestContext(http.MethodGet, "/api/v1/users", nil)
	context.Set(middleware.ContextUserRoleKey, "user")

	handler.ListUsers(context)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if stub.listUsersCalled {
		t.Fatalf("ListUsers service should not be called for non-admin role")
	}
}

func TestAuthHandlerCreateUserCallsServiceForAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stub := &authServiceStub{
		createUserResponse: &dto.UserListItem{
			Username: "operator",
			Role:     "user",
			Status:   "enabled",
		},
	}
	handler := NewAuthHandler(stub)
	body := bytes.NewBufferString(`{"username":"operator","password":"secret-password","role":"user","status":"enabled"}`)
	context, recorder := newAuthHandlerTestContext(http.MethodPost, "/api/v1/users", body)
	context.Set(middleware.ContextUserRoleKey, "admin")

	handler.CreateUser(context)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !stub.createUserCalled {
		t.Fatalf("CreateUser service was not called")
	}
}

func newAuthHandlerTestContext(method, target string, body *bytes.Buffer) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	var requestBody *bytes.Buffer
	if body == nil {
		requestBody = bytes.NewBuffer(nil)
	} else {
		requestBody = body
	}
	context.Request = httptest.NewRequest(method, target, requestBody)
	context.Request.Header.Set("Content-Type", "application/json")
	return context, recorder
}

type authServiceStub struct {
	listUsersCalled    bool
	createUserCalled   bool
	createUserResponse *dto.UserListItem
}

func (s *authServiceStub) Challenge(context.Context, string) (*dto.AuthChallengeResponse, error) {
	return nil, nil
}

func (s *authServiceStub) Login(context.Context, dto.LoginRequest, string, string) (*dto.LoginResponse, error) {
	return nil, nil
}

func (s *authServiceStub) Authenticate(context.Context, string) (*service.AuthenticatedUser, error) {
	return nil, service.ErrUnauthorized
}

func (s *authServiceStub) Logout(context.Context, string) (*dto.LogoutResponse, error) {
	return nil, nil
}

func (s *authServiceStub) CurrentUser(context.Context, int64) (*dto.UserInfo, error) {
	return nil, nil
}

func (s *authServiceStub) ListUsers(context.Context, dto.ListUsersQuery) (*dto.PageResult[dto.UserListItem], error) {
	s.listUsersCalled = true
	return &dto.PageResult[dto.UserListItem]{
		Page:       1,
		PageSize:   10,
		Total:      0,
		TotalPages: 0,
		Items:      []dto.UserListItem{},
	}, nil
}

func (s *authServiceStub) CreateUser(context.Context, dto.CreateUserRequest) (*dto.UserListItem, error) {
	s.createUserCalled = true
	if s.createUserResponse != nil {
		return s.createUserResponse, nil
	}
	return &dto.UserListItem{
		Username: "operator",
		Role:     "user",
		Status:   "enabled",
	}, nil
}
