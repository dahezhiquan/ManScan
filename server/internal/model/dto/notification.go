package dto

import "time"

// SaveNotificationRequest creates or replaces a notification configuration.
type SaveNotificationRequest struct {
	Name        string  `json:"name" binding:"required,max=100"`
	Description *string `json:"description" binding:"omitempty,max=500"`
	Enabled     *bool   `json:"enabled" binding:"required"`
	Event       string  `json:"event" binding:"omitempty,oneof=scan_started high_severity_vulnerability"`
	Webhook     *string `json:"webhook" binding:"omitempty,max=512"`
	Style       string  `json:"style" binding:"omitempty,oneof=blue orange purple red green yellow grey cat_blue cat_orange cat_purple"`
}

// NotificationResponse never returns webhook credentials.
type NotificationResponse struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	Event       string    `json:"event"`
	Webhook     string    `json:"webhook"`
	Style       string    `json:"style"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NotificationStyle describes a header color without an event-specific title.
type NotificationStyle struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
