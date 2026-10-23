package entity_test

import (
	"testing"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestThirdPartyAPIKeyPersistence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 23, 10, 0, 0, 0, time.UTC)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger:  logger.Default.LogMode(logger.Silent),
		NowFunc: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.ThirdPartyAPIKey{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	item := entity.ThirdPartyAPIKey{
		EncryptedKey:       "test-encrypted-api-key",
		PlatformURL:        "https://api.example.com",
		RateLimitPerMinute: 120,
		Description:        "漏洞情报平台",
	}
	if err := db.Create(&item).Error; err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if item.ID <= 0 || item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() {
		t.Fatalf("created item = %+v, want generated ID and timestamps", item)
	}

	var stored entity.ThirdPartyAPIKey
	if err := db.First(&stored, item.ID).Error; err != nil {
		t.Fatalf("First() error = %v", err)
	}
	if stored.EncryptedKey != item.EncryptedKey || stored.PlatformURL != item.PlatformURL || stored.RateLimitPerMinute != item.RateLimitPerMinute || stored.Description != item.Description {
		t.Fatalf("stored item = %+v, want persisted API key configuration", stored)
	}

	updatedAt := stored.UpdatedAt
	now = now.Add(time.Minute)
	if err := db.Model(&stored).Updates(map[string]interface{}{
		"description":           "更新后的作用描述",
		"rate_limit_per_minute": 0,
	}).Error; err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if err := db.First(&stored, item.ID).Error; err != nil {
		t.Fatalf("First() after update error = %v", err)
	}
	if !stored.UpdatedAt.Equal(now) || !stored.UpdatedAt.After(updatedAt) || !stored.CreatedAt.Equal(item.CreatedAt) {
		t.Fatalf("timestamps = %v / %v, want original created_at and advanced updated_at", stored.CreatedAt, stored.UpdatedAt)
	}
	if stored.Description != "更新后的作用描述" || stored.RateLimitPerMinute != 0 {
		t.Fatalf("stored item = %+v, want updated description and unlimited rate", stored)
	}
}
