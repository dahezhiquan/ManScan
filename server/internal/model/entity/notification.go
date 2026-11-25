package entity

import "time"

// Notification stores event subscriptions; webhook credentials are encrypted at rest.
type Notification struct {
	ID               int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Name             string    `gorm:"column:name;size:100;not null"`
	Enabled          bool      `gorm:"column:enabled;not null;default:false;index:idx_notification_event_enabled,priority:2"`
	Event            string    `gorm:"column:event;size:32;not null;index:idx_notification_event_enabled,priority:1"`
	EncryptedWebhook string    `gorm:"column:encrypted_webhook;type:text;not null"`
	Style            string    `gorm:"column:style;size:32;not null"`
	CreatedAt        time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt        time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

// TableName returns the notification configuration table.
func (Notification) TableName() string { return "manscan_notifications" }
