package entity

import "time"

type UserSetting struct {
	ID              int64     `gorm:"column:id;primaryKey;autoIncrement"`
	UserID          int64     `gorm:"column:user_id;uniqueIndex"`
	Theme           string    `gorm:"column:theme;size:32"`
	DarkModeEnabled bool      `gorm:"column:dark_mode_enabled"`
	CreatedAt       time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt       time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

func (UserSetting) TableName() string {
	return "manscan_user_settings"
}
