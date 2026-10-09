package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestAssetHostRepositorySyncObservationsUpsertsAliveHosts(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.AssetHost{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX uk_ip_address ON manscan_asset_host(ip_address)").Error; err != nil {
		t.Fatalf("create unique index error = %v", err)
	}

	createdAt := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	laterAt := createdAt.Add(time.Hour)
	repo := NewAssetHostRepository(db)
	if err := repo.SyncObservations(context.Background(), []AssetHostObservation{{
		IPAddress: "10.72.160.123",
		Region:    "生产内网",
		IsAlive:   true,
	}}, createdAt); err != nil {
		t.Fatalf("SyncObservations() insert error = %v", err)
	}
	if err := repo.SyncObservations(context.Background(), []AssetHostObservation{{
		IPAddress: "10.72.160.123",
		Region:    "核心网段",
		IsAlive:   true,
	}}, laterAt); err != nil {
		t.Fatalf("SyncObservations() update error = %v", err)
	}

	var host entity.AssetHost
	if err := db.Where("ip_address = ?", "10.72.160.123").First(&host).Error; err != nil {
		t.Fatalf("First() error = %v", err)
	}
	if !host.ScanCreatedAt.Equal(createdAt) {
		t.Fatalf("ScanCreatedAt = %v, want first observed time %v", host.ScanCreatedAt, createdAt)
	}
	if host.LastAliveAt == nil || !host.LastAliveAt.Equal(laterAt) {
		t.Fatalf("LastAliveAt = %v, want latest observed time %v", host.LastAliveAt, laterAt)
	}
	if host.Region == nil || *host.Region != "核心网段" {
		t.Fatalf("Region = %v, want updated region", host.Region)
	}
	if !host.IsAlive {
		t.Fatal("IsAlive = false, want true")
	}
}
