package repository

import (
	"context"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AuthChallengeRepository interface {
	Create(ctx context.Context, challenge *entity.AuthChallenge) error
	ConsumeByChallengeID(ctx context.Context, challengeID string, usedAt time.Time) (*entity.AuthChallenge, error)
}

type authChallengeRepository struct {
	db *gorm.DB
}

func NewAuthChallengeRepository(db *gorm.DB) AuthChallengeRepository {
	return &authChallengeRepository{db: db}
}

func (r *authChallengeRepository) Create(ctx context.Context, challenge *entity.AuthChallenge) error {
	return r.db.WithContext(ctx).Create(challenge).Error
}

func (r *authChallengeRepository) ConsumeByChallengeID(ctx context.Context, challengeID string, usedAt time.Time) (*entity.AuthChallenge, error) {
	var challenge entity.AuthChallenge
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("challenge_id = ?", challengeID).
			First(&challenge).Error; err != nil {
			return err
		}
		if challenge.UsedAt != nil || !challenge.ExpiresAt.After(usedAt) {
			return gorm.ErrRecordNotFound
		}
		return tx.Model(&entity.AuthChallenge{}).
			Where("id = ? AND used_at IS NULL", challenge.ID).
			Update("used_at", usedAt).Error
	})
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}
