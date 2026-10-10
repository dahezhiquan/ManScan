package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"strconv"
	"strings"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	authpkg "ManScan/server/internal/pkg/auth"
	"ManScan/server/internal/repository"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService interface {
	Login(ctx context.Context, request dto.LoginRequest, clientIP, userAgent string) (*dto.LoginResponse, error)
	Authenticate(ctx context.Context, token string) (*AuthenticatedUser, error)
	Logout(ctx context.Context, token string) (*dto.LogoutResponse, error)
	CurrentUser(ctx context.Context, userID int64) (*dto.UserInfo, error)
}

type AuthenticatedUser struct {
	User      *entity.User
	TokenID   string
	SessionID int64
}

type authService struct {
	users    repository.UserRepository
	sessions repository.UserSessionRepository
	tokens   authpkg.TokenManager
	tokenTTL time.Duration
}

var ErrInvalidCredentials = errors.New("用户名或密码错误")
var ErrUnauthorized = errors.New("未登录或登录状态已失效")
var ErrUserDisabled = errors.New("用户已被禁用")
var ErrUserLocked = errors.New("账户已锁定")

const (
	userStatusEnabled  = "enabled"
	userStatusDisabled = "disabled"
	userStatusLocked   = "locked"
	defaultUserRole    = "user"
	maxLoginFailures   = 5
)

type LoginFailedError struct {
	RemainingAttempts int
	Locked            bool
}

func (e *LoginFailedError) Error() string {
	if e.Locked {
		return "密码错误次数已达上限，账户已锁定"
	}
	return "用户名或密码错误，还可尝试 " + strconv.Itoa(e.RemainingAttempts) + " 次"
}

func (e *LoginFailedError) Is(target error) bool {
	return target == ErrInvalidCredentials || (e.Locked && target == ErrUserLocked)
}

func NewAuthService(users repository.UserRepository, sessions repository.UserSessionRepository, tokens authpkg.TokenManager, tokenTTL time.Duration) AuthService {
	return &authService{
		users:    users,
		sessions: sessions,
		tokens:   tokens,
		tokenTTL: tokenTTL,
	}
}

func (s *authService) Login(ctx context.Context, request dto.LoginRequest, clientIP, userAgent string) (*dto.LoginResponse, error) {
	username := strings.TrimSpace(request.Username)
	password := request.Password
	if username == "" || password == "" || len(username) > 64 || len(password) > 256 {
		return nil, ErrInvalidCredentials
	}

	user, err := s.users.FindByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if isLockedUser(user) {
		return nil, ErrUserLocked
	}
	if !isEnabledUser(user) {
		return nil, ErrUserDisabled
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		remainingAttempts, locked, recordErr := s.users.RecordFailedLogin(ctx, user.ID, maxLoginFailures)
		if recordErr != nil {
			return nil, recordErr
		}
		return nil, &LoginFailedError{
			RemainingAttempts: remainingAttempts,
			Locked:            locked,
		}
	}

	accessToken, tokenID, expiresAt, err := s.tokens.Generate(user.ID, user.Username, user.Role, s.tokenTTL)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &entity.UserSession{
		UserID:     user.ID,
		TokenID:    tokenID,
		TokenHash:  s.tokens.Hash(accessToken),
		ClientIP:   nullableAuthString(clientIP, 64),
		UserAgent:  nullableAuthString(userAgent, 500),
		ExpiresAt:  expiresAt,
		LastSeenAt: &now,
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, err
	}
	if err := s.users.ResetLoginFailuresAndUpdateLastLoginAt(ctx, user.ID, now); err != nil {
		return nil, err
	}
	user.LastLoginAt = &now

	return &dto.LoginResponse{
		AccessToken: accessToken,
		TokenType:   authpkg.BearerScheme,
		ExpiresAt:   expiresAt,
		User:        toUserInfo(*user),
	}, nil
}

func (s *authService) Authenticate(ctx context.Context, token string) (*AuthenticatedUser, error) {
	claims, err := s.tokens.Parse(token)
	if err != nil {
		return nil, ErrUnauthorized
	}

	now := time.Now()
	session, err := s.sessions.FindActiveByTokenID(ctx, claims.ID, now)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(session.TokenHash), []byte(s.tokens.Hash(token))) != 1 {
		return nil, ErrUnauthorized
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	if user.ID != claims.UserID || !isEnabledUser(user) {
		return nil, ErrUnauthorized
	}
	if err := s.sessions.Touch(ctx, session.ID, now); err != nil {
		return nil, err
	}

	return &AuthenticatedUser{
		User:      user,
		TokenID:   claims.ID,
		SessionID: session.ID,
	}, nil
}

func (s *authService) Logout(ctx context.Context, token string) (*dto.LogoutResponse, error) {
	claims, err := s.tokens.Parse(token)
	if err != nil {
		return nil, ErrUnauthorized
	}

	rowsAffected, err := s.sessions.RevokeByTokenID(ctx, claims.ID, time.Now())
	if err != nil {
		return nil, err
	}
	return &dto.LogoutResponse{Revoked: rowsAffected > 0}, nil
}

func (s *authService) CurrentUser(ctx context.Context, userID int64) (*dto.UserInfo, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	if !isEnabledUser(user) {
		return nil, ErrUnauthorized
	}
	result := toUserInfo(*user)
	return &result, nil
}

func toUserInfo(user entity.User) dto.UserInfo {
	role := strings.TrimSpace(user.Role)
	if role == "" {
		role = defaultUserRole
	}
	return dto.UserInfo{
		ID:          user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		Role:        role,
	}
}

func isEnabledUser(user *entity.User) bool {
	return user != nil && strings.EqualFold(strings.TrimSpace(user.Status), userStatusEnabled)
}

func isLockedUser(user *entity.User) bool {
	return user != nil && strings.EqualFold(strings.TrimSpace(user.Status), userStatusLocked)
}

func nullableAuthString(value string, maxLen int) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if len(value) > maxLen {
		value = value[:maxLen]
	}
	return &value
}
