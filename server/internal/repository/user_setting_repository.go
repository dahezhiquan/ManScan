package repository

import (
	"context"

	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserSettingRepository interface {
	FindByUserID(ctx context.Context, userID int64) (*entity.UserSetting, error)
	UpsertTheme(ctx context.Context, setting *entity.UserSetting) error
}

type userSettingRepository struct {
	db *gorm.DB
}

func NewUserSettingRepository(db *gorm.DB) UserSettingRepository {
	return &userSettingRepository{db: db}
}

func (r *userSettingRepository) FindByUserID(ctx context.Context, userID int64) (*entity.UserSetting, error) {
	var setting entity.UserSetting
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&setting).Error; err != nil {
		return nil, err
	}
	return &setting, nil
}

func (r *userSettingRepository) UpsertTheme(ctx context.Context, setting *entity.UserSetting) error {
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"theme",
			"dark_mode_enabled",
			"updated_at",
		}),
	}).Create(setting).Error
}
