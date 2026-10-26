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
		Role:                "admin",
		Status:              userStatusEnabled,
		FailedLoginAttempts: 2,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user error = %v", err)
	}

	authService := newAuthServiceForTest(db, time.Hour)
	loginResponse, err := authService.Login(context.Background(), newValidLoginRequestForTest(t, authService, " admin ", "secret-password"), "127.0.0.1", "go-test")
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

func TestAuthServiceAuthenticateDoesNotTouchSessionOnEveryRequest(t *testing.T) {
	db := newAuthServiceTestDB(t)
	passwordHash := bcryptHashForTest(t, "secret-password")
	user := entity.User{
		Username:     "admin",
		PasswordHash: passwordHash,
		Role:         "admin",
		Status:       userStatusEnabled,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user error = %v", err)
	}

	authService := newAuthServiceForTest(db, time.Hour)
	loginResponse, err := authService.Login(context.Background(), newValidLoginRequestForTest(t, authService, "admin", "secret-password"), "", "")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if _, err := authService.Authenticate(context.Background(), loginResponse.AccessToken); err != nil {
		t.Fatalf("first Authenticate() error = %v", err)
	}

	var session entity.UserSession
	if err := db.Where("user_id = ?", user.ID).First(&session).Error; err != nil {
		t.Fatalf("Find session error = %v", err)
	}
	if session.LastSeenAt == nil {
		t.Fatal("LastSeenAt is nil after first Authenticate()")
	}
	firstSeenAt := *session.LastSeenAt

	if _, err := authService.Authenticate(context.Background(), loginResponse.AccessToken); err != nil {
		t.Fatalf("second Authenticate() error = %v", err)
	}
	if err := db.Where("user_id = ?", user.ID).First(&session).Error; err != nil {
		t.Fatalf("Find session after second Authenticate() error = %v", err)
	}
	if session.LastSeenAt == nil || !session.LastSeenAt.Equal(firstSeenAt) {
		t.Fatalf("LastSeenAt changed within touch interval: got %v, want %v", session.LastSeenAt, firstSeenAt)
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
	if _, err := authService.Login(context.Background(), newValidLoginRequestForTest(t, authService, "admin", "wrong-password"), "", ""); !errors.Is(err, ErrInvalidCredentials) {
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
	if _, err := authService.Login(context.Background(), newValidLoginRequestForTest(t, authService, "disabled", "secret-password"), "", ""); !errors.Is(err, ErrUserDisabled) {
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
		_, err := authService.Login(context.Background(), newValidLoginRequestForTest(t, authService, "admin", "wrong-password"), "", "")
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

	if _, err := authService.Login(context.Background(), newValidLoginRequestForTest(t, authService, "admin", "secret-password"), "", ""); !errors.Is(err, ErrUserLocked) {
		t.Fatalf("Login() locked user error = %v, want ErrUserLocked", err)
	}
}

func TestAuthServiceChallengeResponse(t *testing.T) {
	db := newAuthServiceTestDB(t)
	authService := newAuthServiceForTest(db, time.Hour)

	challenge, err := authService.Challenge(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Challenge() error = %v", err)
	}
	if challenge.ChallengeID == "" || challenge.ChallengeType != authChallengeTypeOrbitalSlider {
		t.Fatalf("Challenge() = %+v, want orbital slider challenge", challenge)
	}
	if challenge.Scene.Theme == "" || challenge.Scene.CanvasSize <= 0 || challenge.Scene.Radius <= 0 {
		t.Fatalf("Challenge() scene = %+v, want renderable scene", challenge.Scene)
	}
	if !challenge.ExpiresAt.After(time.Now()) {
		t.Fatalf("Challenge() expires_at = %v, want future time", challenge.ExpiresAt)
	}
}

func TestAuthServiceRejectsInvalidChallengeWithoutRecordingPasswordFailure(t *testing.T) {
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
	_, err := authService.Login(context.Background(), dto.LoginRequest{
		Username:    "admin",
		Password:    "wrong-password",
		ChallengeID: "missing-challenge",
		ChallengeAnswer: &dto.LoginChallengeAnswer{
			Angle:          0,
			DragDurationMS: 800,
			Track: []dto.ChallengeTrackPoint{
				{X: 1, Y: 1, T: 0},
				{X: 2, Y: 2, T: 400},
				{X: 3, Y: 3, T: 800},
			},
		},
	}, "", "")
	if !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("Login() error = %v, want ErrInvalidChallenge", err)
	}

	var storedUser entity.User
	if err := db.First(&storedUser, user.ID).Error; err != nil {
		t.Fatalf("Find stored user error = %v", err)
	}
	if storedUser.FailedLoginAttempts != 0 {
		t.Fatalf("FailedLoginAttempts = %d, want 0 when challenge fails", storedUser.FailedLoginAttempts)
	}
}

func TestAuthServiceRejectsReplayedChallenge(t *testing.T) {
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
	request := newValidLoginRequestForTest(t, authService, "admin", "secret-password")
	if _, err := authService.Login(context.Background(), request, "", ""); err != nil {
		t.Fatalf("first Login() error = %v", err)
	}
	if _, err := authService.Login(context.Background(), request, "", ""); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("replayed Login() error = %v, want ErrInvalidChallenge", err)
	}
}

func TestAuthServiceRejectsExpiredChallenge(t *testing.T) {
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
	expiredChallenge := entity.AuthChallenge{
		ChallengeID:     "expired-challenge",
		ChallengeType:   authChallengeTypeOrbitalSlider,
		TargetAngle:     180,
		AnswerTolerance: authChallengeAngleTolerance,
		ExpiresAt:       time.Now().Add(-time.Minute),
	}
	if err := db.Create(&expiredChallenge).Error; err != nil {
		t.Fatalf("Create challenge error = %v", err)
	}

	authService := newAuthServiceForTest(db, time.Hour)
	if _, err := authService.Login(context.Background(), dto.LoginRequest{
		Username:    "admin",
		Password:    "secret-password",
		ChallengeID: expiredChallenge.ChallengeID,
		ChallengeAnswer: &dto.LoginChallengeAnswer{
			Angle:          expiredChallenge.TargetAngle,
			DragDurationMS: 800,
			Track: []dto.ChallengeTrackPoint{
				{X: 1, Y: 1, T: 0},
				{X: 2, Y: 2, T: 400},
				{X: 3, Y: 3, T: 800},
			},
		},
	}, "", ""); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("Login() error = %v, want ErrInvalidChallenge", err)
	}
}

func TestAuthServiceCreateUserAndListUsers(t *testing.T) {
	db := newAuthServiceTestDB(t)
	authService := newAuthServiceForTest(db, time.Hour)

	created, err := authService.CreateUser(context.Background(), dto.CreateUserRequest{
		Username: " operator ",
		Password: "secret-password1!",
		Role:     " USER ",
		Status:   " enabled ",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if created.Username != "operator" || created.Role != defaultUserRole || created.Status != userStatusEnabled || created.LastLoginAt != nil {
		t.Fatalf("CreateUser() = %+v, want normalized user list item", created)
	}

	var storedUser entity.User
	if err := db.Where("username = ?", "operator").First(&storedUser).Error; err != nil {
		t.Fatalf("Find stored user error = %v", err)
	}
	if storedUser.PasswordHash == "secret-password1!" {
		t.Fatalf("PasswordHash stored plaintext password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedUser.PasswordHash), []byte("secret-password1!")); err != nil {
		t.Fatalf("stored PasswordHash does not match original password: %v", err)
	}

	page, err := authService.ListUsers(context.Background(), dto.ListUsersQuery{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("ListUsers() = %+v, want one user", page)
	}
	if page.Items[0].Username != "operator" || page.Items[0].Role != defaultUserRole || page.Items[0].Status != userStatusEnabled {
		t.Fatalf("ListUsers() item = %+v, want created user", page.Items[0])
	}
}

func TestAuthServiceCreateUserRejectsDuplicateUsername(t *testing.T) {
	db := newAuthServiceTestDB(t)
	authService := newAuthServiceForTest(db, time.Hour)
	request := dto.CreateUserRequest{
		Username: "admin",
		Password: "secret-password1!",
		Role:     "admin",
		Status:   userStatusEnabled,
	}
	if _, err := authService.CreateUser(context.Background(), request); err != nil {
		t.Fatalf("first CreateUser() error = %v", err)
	}
	if _, err := authService.CreateUser(context.Background(), request); !errors.Is(err, ErrDuplicateUser) {
		t.Fatalf("duplicate CreateUser() error = %v, want ErrDuplicateUser", err)
	}
}

func TestAuthServiceCreateUserRejectsInvalidInput(t *testing.T) {
	db := newAuthServiceTestDB(t)
	authService := newAuthServiceForTest(db, time.Hour)

	_, err := authService.CreateUser(context.Background(), dto.CreateUserRequest{
		Username: "viewer",
		Password: "secret-password1!",
		Role:     "owner",
		Status:   userStatusEnabled,
	})
	if !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("CreateUser() invalid role error = %v, want ErrInvalidUser", err)
	}

	_, err = authService.CreateUser(context.Background(), dto.CreateUserRequest{
		Username: "viewer",
		Password: "secret-password1!",
		Role:     defaultUserRole,
		Status:   "pending",
	})
	if !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("CreateUser() invalid status error = %v, want ErrInvalidUser", err)
	}

	_, err = authService.CreateUser(context.Background(), dto.CreateUserRequest{
		Username: "viewer",
		Password: "weakpass1",
		Role:     defaultUserRole,
		Status:   userStatusEnabled,
	})
	if !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("CreateUser() weak password error = %v, want ErrInvalidUser", err)
	}
}

func TestAuthServiceUpdateUserUpdatesPasswordRoleAndStatus(t *testing.T) {
	db := newAuthServiceTestDB(t)
	user := entity.User{
		Username:            "operator",
		PasswordHash:        bcryptHashForTest(t, "old-password1!"),
		Role:                defaultUserRole,
		Status:              userStatusLocked,
		FailedLoginAttempts: 5,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user error = %v", err)
	}

	authService := newAuthServiceForTest(db, time.Hour)
	updated, err := authService.UpdateUser(context.Background(), "operator", dto.UpdateUserRequest{
		Password: authStringPtr("new-password1!"),
		Role:     authStringPtr(adminUserRole),
		Status:   authStringPtr(userStatusEnabled),
	})
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}
	if updated.Username != "operator" || updated.Role != adminUserRole || updated.Status != userStatusEnabled {
		t.Fatalf("UpdateUser() = %+v, want updated user", updated)
	}

	var storedUser entity.User
	if err := db.Where("username = ?", "operator").First(&storedUser).Error; err != nil {
		t.Fatalf("Find stored user error = %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedUser.PasswordHash), []byte("new-password1!")); err != nil {
		t.Fatalf("stored PasswordHash does not match updated password: %v", err)
	}
	if storedUser.FailedLoginAttempts != 0 {
		t.Fatalf("FailedLoginAttempts = %d, want 0 after enabling user", storedUser.FailedLoginAttempts)
	}
}

func TestAuthServiceUpdateUserRejectsInvalidInput(t *testing.T) {
	db := newAuthServiceTestDB(t)
	user := entity.User{
		Username:     "operator",
		PasswordHash: bcryptHashForTest(t, "old-password1!"),
		Role:         defaultUserRole,
		Status:       userStatusEnabled,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user error = %v", err)
	}

	authService := newAuthServiceForTest(db, time.Hour)
	if _, err := authService.UpdateUser(context.Background(), "operator", dto.UpdateUserRequest{}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("UpdateUser() empty request error = %v, want ErrInvalidUser", err)
	}
	if _, err := authService.UpdateUser(context.Background(), "operator", dto.UpdateUserRequest{
		Password: authStringPtr("weakpass1"),
	}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("UpdateUser() weak password error = %v, want ErrInvalidUser", err)
	}
}

func TestAuthServiceDeleteUser(t *testing.T) {
	db := newAuthServiceTestDB(t)
	user := entity.User{
		Username:     "operator",
		PasswordHash: bcryptHashForTest(t, "old-password1!"),
		Role:         defaultUserRole,
		Status:       userStatusEnabled,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user error = %v", err)
	}

	authService := newAuthServiceForTest(db, time.Hour)
	deleted, err := authService.DeleteUser(context.Background(), "operator")
	if err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	if deleted.Username != "operator" || deleted.DeletedCount != 1 {
		t.Fatalf("DeleteUser() = %+v, want deleted operator", deleted)
	}
	if err := db.Where("username = ?", "operator").First(&entity.User{}).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("Find deleted user error = %v, want gorm.ErrRecordNotFound", err)
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
	if err := db.AutoMigrate(&entity.User{}, &entity.UserSession{}, &entity.AuthChallenge{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	return db
}

func newAuthServiceForTest(db *gorm.DB, ttl time.Duration) AuthService {
	tokenManager := authpkg.NewJWTManager("test-secret-value-with-at-least-32-bytes", "manscan-server")
	return NewAuthService(
		repository.NewUserRepository(db),
		repository.NewUserSessionRepository(db),
		repository.NewAuthChallengeRepository(db),
		tokenManager,
		ttl,
	)
}

func newValidLoginRequestForTest(t *testing.T, authService AuthService, username, password string) dto.LoginRequest {
	t.Helper()

	challenge, err := authService.Challenge(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Challenge() error = %v", err)
	}
	return dto.LoginRequest{
		Username:    username,
		Password:    password,
		ChallengeID: challenge.ChallengeID,
		ChallengeAnswer: &dto.LoginChallengeAnswer{
			Angle:          challenge.Scene.TargetAngle,
			DragDurationMS: 800,
			Track: []dto.ChallengeTrackPoint{
				{X: 160, Y: 160, T: 0},
				{X: 190, Y: 148, T: 320},
				{X: 220, Y: 130, T: 800},
			},
		},
	}
}

func bcryptHashForTest(t *testing.T, password string) string {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	return string(hash)
}

func authStringPtr(value string) *string {
	return &value
}
