package entity

import "time"

// Notification stores event subscriptions with plaintext webhook addresses.
type Notification struct {
	ID          int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Name        string    `gorm:"column:name;size:100;not null"`
	Description string    `gorm:"column:description;size:500;not null;default:'';comment:通知描述"`
	Enabled     bool      `gorm:"column:enabled;not null;default:false;index:idx_notification_event_enabled,priority:2"`
	Event       string    `gorm:"column:event;size:32;not null;index:idx_notification_event_enabled,priority:1"`
	Webhook     string    `gorm:"column:webhook;type:text;not null;comment:飞书机器人 Webhook 地址（明文）"`
	Style       string    `gorm:"column:style;size:32;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt   time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

// TableName returns the notification configuration table.
func (Notification) TableName() string { return "manscan_notifications" }
