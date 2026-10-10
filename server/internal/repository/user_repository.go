package repository

import (
	"context"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserRepository interface {
	FindByID(ctx context.Context, userID int64) (*entity.User, error)
	FindByUsername(ctx context.Context, username string) (*entity.User, error)
	RecordFailedLogin(ctx context.Context, userID int64, maxAttempts int) (int, bool, error)
	ResetLoginFailuresAndUpdateLastLoginAt(ctx context.Context, userID int64, loggedInAt time.Time) error
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) FindByID(ctx context.Context, userID int64) (*entity.User, error) {
	var user entity.User
	if err := r.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) FindByUsername(ctx context.Context, username string) (*entity.User, error) {
	var user entity.User
	if err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) RecordFailedLogin(ctx context.Context, userID int64, maxAttempts int) (int, bool, error) {
	var remainingAttempts int
	var locked bool
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user entity.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, userID).Error; err != nil {
			return err
		}

		nextAttempts := user.FailedLoginAttempts + 1
		if nextAttempts >= maxAttempts {
			locked = true
			remainingAttempts = 0
		} else {
			remainingAttempts = maxAttempts - nextAttempts
		}

		updates := map[string]interface{}{
			"failed_login_attempts": nextAttempts,
		}
		if locked {
			updates["status"] = "locked"
		}

		return tx.Model(&entity.User{}).Where("id = ?", userID).Updates(updates).Error
	})
	if err != nil {
		return 0, false, err
	}
	return remainingAttempts, locked, nil
}

func (r *userRepository) ResetLoginFailuresAndUpdateLastLoginAt(ctx context.Context, userID int64, loggedInAt time.Time) error {
	return r.db.WithContext(ctx).Model(&entity.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"failed_login_attempts": 0,
			"last_login_at":         loggedInAt,
		}).Error
}
