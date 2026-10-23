package entity

import "time"

// ThirdPartyAPIKey 保存第三方平台的 API Key 配置。
type ThirdPartyAPIKey struct {
	ID                 int64     `gorm:"column:id;primaryKey;autoIncrement"`
	EncryptedKey       string    `json:"-" gorm:"column:encrypted_key;type:varchar(1024);not null"` // 仅保存 AES-GCM 密文。
	PlatformURL        string    `gorm:"column:platform_url;type:varchar(2048);not null"`
	RateLimitPerMinute uint32    `gorm:"column:rate_limit_per_minute;type:int unsigned;not null;default:0"` // 0 表示不限制。
	CreatedAt          time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt          time.Time `gorm:"column:updated_at;autoUpdateTime"`
	Description        string    `gorm:"column:description;type:varchar(512);not null;default:''"`
}

// TableName 返回第三方 API Key 配置表名。
func (ThirdPartyAPIKey) TableName() string {
	return "manscan_third_party_api_keys"
}
