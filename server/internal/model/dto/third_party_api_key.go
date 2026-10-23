package dto

import "time"

type ListThirdPartyAPIKeysQuery struct {
	Page     int
	PageSize int
}

type ThirdPartyAPIKeyListItem struct {
	ID                 int64     `json:"id"`
	PlatformURL        string    `json:"platform_url"`
	RateLimitPerMinute uint32    `json:"rate_limit_per_minute"`
	Description        string    `json:"description"`
	KeyConfigured      bool      `json:"key_configured"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// ThirdPartyAPIKeyPlaintextResponse 返回受控读取的第三方 API Key 明文。
type ThirdPartyAPIKeyPlaintextResponse struct {
	Key string `json:"key"`
}

type CreateThirdPartyAPIKeyRequest struct {
	Key                string `json:"key" binding:"required,max=512"`
	PlatformURL        string `json:"platform_url" binding:"required,max=2048"`
	RateLimitPerMinute uint32 `json:"rate_limit_per_minute"`
	Description        string `json:"description" binding:"max=512"`
}

type UpdateThirdPartyAPIKeyRequest struct {
	Key                *string `json:"key" binding:"omitempty,max=512"`
	PlatformURL        string  `json:"platform_url" binding:"required,max=2048"`
	RateLimitPerMinute uint32  `json:"rate_limit_per_minute"`
	Description        string  `json:"description" binding:"max=512"`
}

type DeleteThirdPartyAPIKeyResponse struct {
	ID           int64 `json:"id"`
	DeletedCount int64 `json:"deleted_count"`
}
