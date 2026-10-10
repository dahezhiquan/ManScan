package entity

import "time"

type UserSession struct {
	ID         int64      `gorm:"column:id;primaryKey;autoIncrement"`
	UserID     int64      `gorm:"column:user_id"`
	TokenID    string     `gorm:"column:token_id"`
	TokenHash  string     `gorm:"column:token_hash"`
	ClientIP   *string    `gorm:"column:client_ip"`
	UserAgent  *string    `gorm:"column:user_agent"`
	ExpiresAt  time.Time  `gorm:"column:expires_at"`
	RevokedAt  *time.Time `gorm:"column:revoked_at"`
	LastSeenAt *time.Time `gorm:"column:last_seen_at"`
	CreatedAt  time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;autoUpdateTime"`
}

func (UserSession) TableName() string {
	return "manscan_user_sessions"
}
