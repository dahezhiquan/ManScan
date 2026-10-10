package repository

import (
	"context"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
)

type UserSessionRepository interface {
	Create(ctx context.Context, session *entity.UserSession) error
	FindActiveByTokenID(ctx context.Context, tokenID string, now time.Time) (*entity.UserSession, error)
	RevokeByTokenID(ctx context.Context, tokenID string, revokedAt time.Time) (int64, error)
	Touch(ctx context.Context, sessionID int64, seenAt time.Time) error
}

type userSessionRepository struct {
	db *gorm.DB
}

func NewUserSessionRepository(db *gorm.DB) UserSessionRepository {
	return &userSessionRepository{db: db}
}

func (r *userSessionRepository) Create(ctx context.Context, session *entity.UserSession) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *userSessionRepository) FindActiveByTokenID(ctx context.Context, tokenID string, now time.Time) (*entity.UserSession, error) {
	var session entity.UserSession
	if err := r.db.WithContext(ctx).
		Where("token_id = ? AND revoked_at IS NULL AND expires_at > ?", tokenID, now).
		First(&session).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *userSessionRepository) RevokeByTokenID(ctx context.Context, tokenID string, revokedAt time.Time) (int64, error) {
	result := r.db.WithContext(ctx).Model(&entity.UserSession{}).
		Where("token_id = ? AND revoked_at IS NULL", tokenID).
		Update("revoked_at", revokedAt)
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}

func (r *userSessionRepository) Touch(ctx context.Context, sessionID int64, seenAt time.Time) error {
	return r.db.WithContext(ctx).Model(&entity.UserSession{}).
		Where("id = ?", sessionID).
		Update("last_seen_at", seenAt).Error
}
