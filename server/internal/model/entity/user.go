package entity

import "time"

type User struct {
	ID                  int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Username            string     `gorm:"column:username;size:64"`
	PasswordHash        string     `gorm:"column:password_hash;size:255"`
	DisplayName         string     `gorm:"column:display_name;size:64"`
	Role                string     `gorm:"column:role;size:32"`
	Status              string     `gorm:"column:status;size:16"`
	FailedLoginAttempts int        `gorm:"column:failed_login_attempts"`
	LastLoginAt         *time.Time `gorm:"column:last_login_at"`
	CreatedAt           time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt           time.Time  `gorm:"column:updated_at;autoUpdateTime"`
}

func (User) TableName() string {
	return "manscan_users"
}
