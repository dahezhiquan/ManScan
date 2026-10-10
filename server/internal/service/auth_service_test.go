package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	authpkg "ManScan/server/internal/pkg/auth"
	"ManScan/server/internal/repository"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestAuthServiceLoginAuthenticateAndLogout(t *testing.T) {
	db := newAuthServiceTestDB(t)
	passwordHash := bcryptHashForTest(t, "secret-password")
	user := entity.User{
		Username:            "admin",
		PasswordHash:        passwordHash,
		DisplayName:         "管理员",
		Role:                "admin",
		Status:              userStatusEnabled,
		FailedLoginAttempts: 2,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user error = %v", err)
	}

	authService := newAuthServiceForTest(db, time.Hour)
	loginResponse, err := authService.Login(context.Background(), dto.LoginRequest{
		Username: " admin ",
		Password: "secret-password",
	}, "127.0.0.1", "go-test")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if loginResponse.AccessToken == "" || loginResponse.TokenType != authpkg.BearerScheme {
		t.Fatalf("Login() response = %+v, want bearer token", loginResponse)
	}
	if loginResponse.User.ID != user.ID || loginResponse.User.Role != "admin" {
		t.Fatalf("Login() user = %+v, want admin user", loginResponse.User)
	}
	var storedUser entity.User
	if err := db.First(&storedUser, user.ID).Error; err != nil {
		t.Fatalf("Find stored user error = %v", err)
	}
	if storedUser.FailedLoginAttempts != 0 {
		t.Fatalf("FailedLoginAttempts = %d, want 0 after successful login", storedUser.FailedLoginAttempts)
	}

	authenticated, err := authService.Authenticate(context.Background(), loginResponse.AccessToken)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if authenticated.User.ID != user.ID || authenticated.SessionID <= 0 {
		t.Fatalf("Authenticate() = %+v, want user and session", authenticated)
	}

	logoutResponse, err := authService.Logout(context.Background(), loginResponse.AccessToken)
	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if !logoutResponse.Revoked {
		t.Fatalf("Logout() revoked = false, want true")
	}
	if _, err := authService.Authenticate(context.Background(), loginResponse.AccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authenticate() after logout error = %v, want ErrUnauthorized", err)
	}
}

func TestAuthServiceRejectsInvalidCredentials(t *testing.T) {
	db := newAuthServiceTestDB(t)
	user := entity.User{
		Username:     "admin",
		PasswordHash: bcryptHashForTest(t, "secret-password"),
		Role:         "admin",
		Status:       userStatusEnabled,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user error = %v", err)
	}

	authService := newAuthServiceForTest(db, time.Hour)
	if _, err := authService.Login(context.Background(), dto.LoginRequest{
		Username: "admin",
		Password: "wrong-password",
	}, "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthServiceRejectsDisabledUser(t *testing.T) {
	db := newAuthServiceTestDB(t)
	user := entity.User{
		Username:     "disabled",
		PasswordHash: bcryptHashForTest(t, "secret-password"),
		Role:         "user",
		Status:       userStatusDisabled,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user error = %v", err)
	}

	authService := newAuthServiceForTest(db, time.Hour)
	if _, err := authService.Login(context.Background(), dto.LoginRequest{
		Username: "disabled",
		Password: "secret-password",
	}, "", ""); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("Login() error = %v, want ErrUserDisabled", err)
	}
}

func TestAuthServiceFailedPasswordTracksRemainingAttemptsAndLocksUser(t *testing.T) {
	db := newAuthServiceTestDB(t)
	user := entity.User{
		Username:     "admin",
		PasswordHash: bcryptHashForTest(t, "secret-password"),
		Role:         "admin",
		Status:       userStatusEnabled,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user error = %v", err)
	}

	authService := newAuthServiceForTest(db, time.Hour)
	for i := 1; i <= maxLoginFailures; i++ {
		_, err := authService.Login(context.Background(), dto.LoginRequest{
			Username: "admin",
			Password: "wrong-password",
		}, "", "")
		var loginFailedErr *LoginFailedError
		if !errors.As(err, &loginFailedErr) {
			t.Fatalf("Login() attempt %d error = %v, want LoginFailedError", i, err)
		}

		wantRemaining := maxLoginFailures - i
		if loginFailedErr.RemainingAttempts != wantRemaining {
			t.Fatalf("attempt %d remaining = %d, want %d", i, loginFailedErr.RemainingAttempts, wantRemaining)
		}
		if loginFailedErr.Locked != (i == maxLoginFailures) {
			t.Fatalf("attempt %d locked = %v, want %v", i, loginFailedErr.Locked, i == maxLoginFailures)
		}
	}

	var storedUser entity.User
	if err := db.First(&storedUser, user.ID).Error; err != nil {
		t.Fatalf("Find stored user error = %v", err)
	}
	if storedUser.Status != userStatusLocked {
		t.Fatalf("user status = %q, want locked", storedUser.Status)
	}
	if storedUser.FailedLoginAttempts != maxLoginFailures {
		t.Fatalf("failed attempts = %d, want %d", storedUser.FailedLoginAttempts, maxLoginFailures)
	}

	if _, err := authService.Login(context.Background(), dto.LoginRequest{
		Username: "admin",
		Password: "secret-password",
	}, "", ""); !errors.Is(err, ErrUserLocked) {
		t.Fatalf("Login() locked user error = %v, want ErrUserLocked", err)
	}
}

func newAuthServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "auth.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.User{}, &entity.UserSession{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	return db
}

func newAuthServiceForTest(db *gorm.DB, ttl time.Duration) AuthService {
	tokenManager := authpkg.NewJWTManager("test-secret-value-with-at-least-32-bytes", "manscan-server")
	return NewAuthService(
		repository.NewUserRepository(db),
		repository.NewUserSessionRepository(db),
		tokenManager,
		ttl,
	)
}

func bcryptHashForTest(t *testing.T, password string) string {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	return string(hash)
}
