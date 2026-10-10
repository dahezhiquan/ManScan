package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const BearerScheme = "Bearer"

var ErrInvalidToken = errors.New("invalid token")

type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type TokenManager interface {
	Generate(userID int64, username, role string, ttl time.Duration) (string, string, time.Time, error)
	Parse(token string) (*Claims, error)
	Hash(token string) string
}

type JWTManager struct {
	secret []byte
	issuer string
}

func NewJWTManager(secret, issuer string) *JWTManager {
	return &JWTManager{
		secret: []byte(secret),
		issuer: strings.TrimSpace(issuer),
	}
}

func (m *JWTManager) Generate(userID int64, username, role string, ttl time.Duration) (string, string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(ttl)
	tokenID := uuid.NewString()
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Issuer:    m.issuer,
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	signedToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return signedToken, tokenID, expiresAt, nil
}

func (m *JWTManager) Parse(tokenValue string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenValue, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalidToken
		}
		return m.secret, nil
	}, jwt.WithIssuer(m.issuer))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	if claims.UserID <= 0 || strings.TrimSpace(claims.ID) == "" {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func (m *JWTManager) Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func ExtractBearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}

	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], BearerScheme) || strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return parts[1], true
}
