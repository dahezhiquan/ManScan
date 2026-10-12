package repository

import (
	"context"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserRepository interface {
	Create(ctx context.Context, user *entity.User) error
	Update(ctx context.Context, user *entity.User) error
	Delete(ctx context.Context, userID int64) (int64, error)
	FindByID(ctx context.Context, userID int64) (*entity.User, error)
	FindByUsername(ctx context.Context, username string) (*entity.User, error)
	List(ctx context.Context, page, pageSize int) ([]entity.User, int, error)
	RecordFailedLogin(ctx context.Context, userID int64, maxAttempts int) (int, bool, error)
	ResetLoginFailuresAndUpdateLastLoginAt(ctx context.Context, userID int64, loggedInAt time.Time) error
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *entity.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepository) Update(ctx context.Context, user *entity.User) error {
	return r.db.WithContext(ctx).Model(&entity.User{}).
		Where("id = ?", user.ID).
		Updates(map[string]interface{}{
			"password_hash":         user.PasswordHash,
			"role":                  user.Role,
			"status":                user.Status,
			"failed_login_attempts": user.FailedLoginAttempts,
		}).Error
}

func (r *userRepository) Delete(ctx context.Context, userID int64) (int64, error) {
	result := r.db.WithContext(ctx).Delete(&entity.User{}, userID)
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
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

func (r *userRepository) List(ctx context.Context, page, pageSize int) ([]entity.User, int, error) {
	var total int64
	if err := r.db.WithContext(ctx).Model(&entity.User{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var users []entity.User
	offset := (page - 1) * pageSize
	if err := r.db.WithContext(ctx).Order("id ASC").Offset(offset).Limit(pageSize).Find(&users).Error; err != nil {
		return nil, 0, err
	}
	return users, int(total), nil
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
