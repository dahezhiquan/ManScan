package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	authpkg "ManScan/server/internal/pkg/auth"
	"ManScan/server/internal/repository"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService interface {
	Challenge(ctx context.Context, clientIP string) (*dto.AuthChallengeResponse, error)
	Login(ctx context.Context, request dto.LoginRequest, clientIP, userAgent string) (*dto.LoginResponse, error)
	Authenticate(ctx context.Context, token string) (*AuthenticatedUser, error)
	Logout(ctx context.Context, token string) (*dto.LogoutResponse, error)
	CurrentUser(ctx context.Context, userID int64) (*dto.UserInfo, error)
	ListUsers(ctx context.Context, query dto.ListUsersQuery) (*dto.PageResult[dto.UserListItem], error)
	CreateUser(ctx context.Context, request dto.CreateUserRequest) (*dto.UserListItem, error)
	UpdateUser(ctx context.Context, username string, request dto.UpdateUserRequest) (*dto.UserListItem, error)
	DeleteUser(ctx context.Context, username string) (*dto.DeleteUserResponse, error)
}

type AuthenticatedUser struct {
	User      *entity.User
	TokenID   string
	SessionID int64
}

type authService struct {
	users      repository.UserRepository
	sessions   repository.UserSessionRepository
	challenges repository.AuthChallengeRepository
	tokens     authpkg.TokenManager
	tokenTTL   time.Duration
}

var ErrInvalidCredentials = errors.New("用户名或密码错误")
var ErrUnauthorized = errors.New("未登录或登录状态已失效")
var ErrUserDisabled = errors.New("用户已被禁用")
var ErrUserLocked = errors.New("账户已锁定")
var ErrInvalidChallenge = errors.New("验证码校验失败，请刷新后重试")
var ErrInvalidUser = errors.New("用户参数不合法")
var ErrDuplicateUser = errors.New("用户名已存在")

const (
	userStatusEnabled                 = "enabled"
	userStatusDisabled                = "disabled"
	userStatusLocked                  = "locked"
	defaultUserRole                   = "user"
	adminUserRole                     = "admin"
	maxLoginFailures                  = 5
	minCreateUserPasswordLength       = 8
	maxBCryptPasswordLength           = 72
	authChallengeTypeOrbitalSlider    = "orbital_slider"
	authChallengeThemeNeoOrbit        = "neo_orbit"
	authChallengeTTL                  = 5 * time.Minute
	authChallengeAngleTolerance       = 6.0
	authChallengeMinDragDurationMS    = 300
	authChallengeMaxDragDurationMS    = 10000
	authChallengeMinTrackPoints       = 3
	authChallengeMaxTrackPoints       = 240
	authChallengeCanvasSize           = 320
	authChallengeOrbitRadius          = 112
	authChallengeTrackCoordinateLimit = 10000
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

func NewAuthService(users repository.UserRepository, sessions repository.UserSessionRepository, challenges repository.AuthChallengeRepository, tokens authpkg.TokenManager, tokenTTL time.Duration) AuthService {
	return &authService{
		users:      users,
		sessions:   sessions,
		challenges: challenges,
		tokens:     tokens,
		tokenTTL:   tokenTTL,
	}
}

func (s *authService) Challenge(ctx context.Context, clientIP string) (*dto.AuthChallengeResponse, error) {
	targetAngle, err := secureRandomAngle()
	if err != nil {
		return nil, err
	}
	startAngle, err := secureRandomAngle()
	if err != nil {
		return nil, err
	}
	sceneSeed, err := secureRandomInt64()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	challenge := &entity.AuthChallenge{
		ChallengeID:     uuid.NewString(),
		ChallengeType:   authChallengeTypeOrbitalSlider,
		TargetAngle:     targetAngle,
		AnswerTolerance: authChallengeAngleTolerance,
		SceneSeed:       sceneSeed,
		ClientIP:        nullableAuthString(clientIP, 64),
		ExpiresAt:       now.Add(authChallengeTTL),
	}
	if err := s.challenges.Create(ctx, challenge); err != nil {
		return nil, err
	}

	return &dto.AuthChallengeResponse{
		ChallengeID:   challenge.ChallengeID,
		ChallengeType: challenge.ChallengeType,
		ExpiresAt:     challenge.ExpiresAt,
		Scene: dto.OrbitalSliderScene{
			Theme:       authChallengeThemeNeoOrbit,
			Seed:        sceneSeed,
			CanvasSize:  authChallengeCanvasSize,
			CenterX:     authChallengeCanvasSize / 2,
			CenterY:     authChallengeCanvasSize / 2,
			Radius:      authChallengeOrbitRadius,
			StartAngle:  roundAngle(startAngle),
			TargetAngle: roundAngle(targetAngle),
			DecoyAngles: buildDecoyAngles(targetAngle),
		},
		Requirements: dto.ChallengeRules{
			AngleTolerance:    authChallengeAngleTolerance,
			MinDragDurationMS: authChallengeMinDragDurationMS,
			MaxDragDurationMS: authChallengeMaxDragDurationMS,
			MinTrackPoints:    authChallengeMinTrackPoints,
			MaxTrackPoints:    authChallengeMaxTrackPoints,
		},
	}, nil
}

func (s *authService) Login(ctx context.Context, request dto.LoginRequest, clientIP, userAgent string) (*dto.LoginResponse, error) {
	username := strings.TrimSpace(request.Username)
	password := request.Password
	if username == "" || password == "" || len(username) > 64 || len(password) > 256 {
		return nil, ErrInvalidCredentials
	}
	if err := s.validateChallenge(ctx, request); err != nil {
		return nil, err
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

func (s *authService) validateChallenge(ctx context.Context, request dto.LoginRequest) error {
	challengeID := strings.TrimSpace(request.ChallengeID)
	if challengeID == "" || len(challengeID) > 64 || request.ChallengeAnswer == nil {
		return ErrInvalidChallenge
	}

	challenge, err := s.challenges.ConsumeByChallengeID(ctx, challengeID, time.Now())
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrInvalidChallenge
		}
		return err
	}
	if challenge.ChallengeType != authChallengeTypeOrbitalSlider {
		return ErrInvalidChallenge
	}
	if !isValidChallengeAnswer(*request.ChallengeAnswer, challenge.TargetAngle, challenge.AnswerTolerance) {
		return ErrInvalidChallenge
	}
	return nil
}

func isValidChallengeAnswer(answer dto.LoginChallengeAnswer, targetAngle, tolerance float64) bool {
	if math.IsNaN(answer.Angle) || math.IsInf(answer.Angle, 0) {
		return false
	}
	if angleDistance(answer.Angle, targetAngle) > tolerance {
		return false
	}
	if answer.DragDurationMS < authChallengeMinDragDurationMS || answer.DragDurationMS > authChallengeMaxDragDurationMS {
		return false
	}
	if len(answer.Track) < authChallengeMinTrackPoints || len(answer.Track) > authChallengeMaxTrackPoints {
		return false
	}

	lastT := -1
	for _, point := range answer.Track {
		if point.T < 0 || point.T < lastT {
			return false
		}
		if absInt(point.X) > authChallengeTrackCoordinateLimit || absInt(point.Y) > authChallengeTrackCoordinateLimit {
			return false
		}
		lastT = point.T
	}
	return lastT <= answer.DragDurationMS+500
}

func buildDecoyAngles(targetAngle float64) []float64 {
	offsets := []float64{47, 119, 203, 291}
	decoys := make([]float64, 0, len(offsets))
	for _, offset := range offsets {
		decoys = append(decoys, roundAngle(targetAngle+offset))
	}
	return decoys
}

func angleDistance(left, right float64) float64 {
	diff := math.Mod(math.Abs(normalizeAngle(left)-normalizeAngle(right)), 360)
	if diff > 180 {
		return 360 - diff
	}
	return diff
}

func normalizeAngle(angle float64) float64 {
	value := math.Mod(angle, 360)
	if value < 0 {
		return value + 360
	}
	return value
}

func roundAngle(angle float64) float64 {
	return math.Round(normalizeAngle(angle)*100) / 100
}

func secureRandomAngle() (float64, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(36000))
	if err != nil {
		return 0, err
	}
	return float64(value.Int64()) / 100, nil
}

func secureRandomInt64() (int64, error) {
	const maxInt64 = int64(1<<63 - 1)
	value, err := rand.Int(rand.Reader, big.NewInt(maxInt64))
	if err != nil {
		return 0, err
	}
	return value.Int64(), nil
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
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

func (s *authService) ListUsers(ctx context.Context, query dto.ListUsersQuery) (*dto.PageResult[dto.UserListItem], error) {
	if query.Page <= 0 || query.PageSize <= 0 {
		return nil, ErrInvalidUser
	}
	users, total, err := s.users.List(ctx, query.Page, query.PageSize)
	if err != nil {
		return nil, err
	}

	items := make([]dto.UserListItem, 0, len(users))
	for _, user := range users {
		items = append(items, toUserListItem(user))
	}

	totalPages := 0
	if total > 0 {
		totalPages = (total + query.PageSize - 1) / query.PageSize
	}
	return &dto.PageResult[dto.UserListItem]{
		Page:       query.Page,
		PageSize:   query.PageSize,
		Total:      total,
		TotalPages: totalPages,
		Items:      items,
	}, nil
}

func (s *authService) CreateUser(ctx context.Context, request dto.CreateUserRequest) (*dto.UserListItem, error) {
	username := strings.TrimSpace(request.Username)
	password := request.Password
	role := normalizeUserRole(request.Role)
	if role == "" {
		role = defaultUserRole
	}
	status := normalizeCreateUserStatus(request.Status)
	if status == "" {
		status = userStatusEnabled
	}
	if username == "" || len(username) > 64 || !isValidCreateUserPassword(password) || !isValidUserRole(role) || !isValidUserStatus(status) {
		return nil, ErrInvalidUser
	}
	if _, err := s.users.FindByUsername(ctx, username); err == nil {
		return nil, ErrDuplicateUser
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user := &entity.User{
		Username:     username,
		PasswordHash: string(passwordHash),
		Role:         role,
		Status:       status,
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}
	result := toUserListItem(*user)
	return &result, nil
}

func (s *authService) UpdateUser(ctx context.Context, username string, request dto.UpdateUserRequest) (*dto.UserListItem, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 {
		return nil, ErrInvalidUser
	}
	user, err := s.users.FindByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	changed := false
	if request.Password != nil {
		if !isValidCreateUserPassword(*request.Password) {
			return nil, ErrInvalidUser
		}
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(*request.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		user.PasswordHash = string(passwordHash)
		changed = true
	}
	if request.Role != nil {
		role := normalizeUserRole(*request.Role)
		if !isValidUserRole(role) {
			return nil, ErrInvalidUser
		}
		user.Role = role
		changed = true
	}
	if request.Status != nil {
		status := normalizeCreateUserStatus(*request.Status)
		if !isValidUserStatus(status) {
			return nil, ErrInvalidUser
		}
		user.Status = status
		if status == userStatusEnabled {
			user.FailedLoginAttempts = 0
		}
		changed = true
	}
	if !changed {
		return nil, ErrInvalidUser
	}

	if err := s.users.Update(ctx, user); err != nil {
		return nil, err
	}
	result := toUserListItem(*user)
	return &result, nil
}

func (s *authService) DeleteUser(ctx context.Context, username string) (*dto.DeleteUserResponse, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 {
		return nil, ErrInvalidUser
	}
	user, err := s.users.FindByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	deletedCount, err := s.users.Delete(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return &dto.DeleteUserResponse{
		Username:     user.Username,
		DeletedCount: deletedCount,
	}, nil
}

func toUserInfo(user entity.User) dto.UserInfo {
	role := strings.TrimSpace(user.Role)
	if role == "" {
		role = defaultUserRole
	}
	return dto.UserInfo{
		ID:       user.ID,
		Username: user.Username,
		Role:     role,
	}
}

func toUserListItem(user entity.User) dto.UserListItem {
	role := normalizeUserRole(user.Role)
	if role == "" {
		role = defaultUserRole
	}
	status := normalizeCreateUserStatus(user.Status)
	if status == "" {
		status = userStatusEnabled
	}
	return dto.UserListItem{
		Username:    user.Username,
		Role:        role,
		Status:      status,
		LastLoginAt: user.LastLoginAt,
	}
}

func normalizeUserRole(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}

func normalizeCreateUserStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

func isValidUserRole(role string) bool {
	switch role {
	case defaultUserRole, adminUserRole:
		return true
	default:
		return false
	}
}

func isValidUserStatus(status string) bool {
	switch status {
	case userStatusEnabled, userStatusDisabled, userStatusLocked:
		return true
	default:
		return false
	}
}

func isValidCreateUserPassword(password string) bool {
	if utf8.RuneCountInString(password) <= minCreateUserPasswordLength || len(password) > maxBCryptPasswordLength {
		return false
	}

	hasLetter := false
	hasDigit := false
	hasPunctuation := false
	for _, r := range password {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasPunctuation = true
		}
	}
	return hasLetter && hasDigit && hasPunctuation
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
