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

func TestAssetHostPortRepositorySyncObservationsUpsertsAlivePorts(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.AssetHostPort{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX uk_ip_protocol_port ON manscan_asset_host_port(ip_address, port_protocol, port_number)").Error; err != nil {
		t.Fatalf("create unique index error = %v", err)
	}

	createdAt := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	laterAt := createdAt.Add(time.Hour)
	repo := NewAssetHostPortRepository(db)
	if err := repo.SyncObservations(context.Background(), []AssetHostPortObservation{{
		IPAddress:   "10.72.160.153",
		Region:      "生产内网",
		PortNumber:  8670,
		ServiceName: "redis",
		AppName:     "redis",
		IsAlive:     true,
	}}, createdAt); err != nil {
		t.Fatalf("SyncObservations() insert error = %v", err)
	}
	if err := repo.SyncObservations(context.Background(), []AssetHostPortObservation{{
		IPAddress:   "10.72.160.153",
		Region:      "生产内网",
		PortNumber:  8670,
		ServiceName: "redis",
		AppName:     "redis",
		AppVersion:  "7.2.1",
		IsAlive:     true,
	}}, laterAt); err != nil {
		t.Fatalf("SyncObservations() update error = %v", err)
	}

	var port entity.AssetHostPort
	if err := db.Where("ip_address = ? AND port_protocol = ? AND port_number = ?", "10.72.160.153", "", 8670).First(&port).Error; err != nil {
		t.Fatalf("First() error = %v", err)
	}
	if port.PortProtocol != "" {
		t.Fatalf("PortProtocol = %q, want empty default", port.PortProtocol)
	}
	if !port.PortCreatedAt.Equal(createdAt) {
		t.Fatalf("PortCreatedAt = %v, want first observed time %v", port.PortCreatedAt, createdAt)
	}
	if port.LastAliveAt == nil || !port.LastAliveAt.Equal(laterAt) {
		t.Fatalf("LastAliveAt = %v, want latest observed time %v", port.LastAliveAt, laterAt)
	}
	if port.ServiceName == nil || *port.ServiceName != "redis" {
		t.Fatalf("ServiceName = %v, want redis", port.ServiceName)
	}
	if port.AppVersion == nil || *port.AppVersion != "7.2.1" {
		t.Fatalf("AppVersion = %v, want 7.2.1", port.AppVersion)
	}
	if !port.IsAlive {
		t.Fatal("IsAlive = false, want true")
	}
}

func TestAssetHostPortRepositoryMarkHTTPPortsInactiveUpdatesExistingHTTPOnly(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.AssetHostPort{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	httpName := "http"
	redisName := "redis"
	if err := db.Create(&[]entity.AssetHostPort{
		{
			IPAddress:     "10.72.160.153",
			LastAliveAt:   &now,
			PortCreatedAt: now,
			PortNumber:    80,
			ServiceName:   &httpName,
			AppName:       &httpName,
			IsAlive:       true,
		},
		{
			IPAddress:     "10.72.160.153",
			LastAliveAt:   &now,
			PortCreatedAt: now,
			PortNumber:    6379,
			ServiceName:   &redisName,
			AppName:       &redisName,
			IsAlive:       true,
		},
	}).Error; err != nil {
		t.Fatalf("Create host ports error = %v", err)
	}

	repo := NewAssetHostPortRepository(db)
	if err := repo.MarkHTTPPortsInactive(context.Background(), []AssetHostPortObservation{
		{IPAddress: "10.72.160.153", PortNumber: 80},
		{IPAddress: "10.72.160.153", PortNumber: 6379},
		{IPAddress: "10.72.160.200", PortNumber: 80},
	}); err != nil {
		t.Fatalf("MarkHTTPPortsInactive() error = %v", err)
	}

	var httpPort entity.AssetHostPort
	if err := db.Where("ip_address = ? AND port_number = ?", "10.72.160.153", 80).First(&httpPort).Error; err != nil {
		t.Fatalf("First http port error = %v", err)
	}
	if httpPort.IsAlive {
		t.Fatal("http port IsAlive = true, want false")
	}

	var redisPort entity.AssetHostPort
	if err := db.Where("ip_address = ? AND port_number = ?", "10.72.160.153", 6379).First(&redisPort).Error; err != nil {
		t.Fatalf("First redis port error = %v", err)
	}
	if !redisPort.IsAlive {
		t.Fatal("redis port IsAlive = false, want true")
	}

	var count int64
	if err := db.Model(&entity.AssetHostPort{}).Where("ip_address = ?", "10.72.160.200").Count(&count).Error; err != nil {
		t.Fatalf("Count non-existing port error = %v", err)
	}
	if count != 0 {
		t.Fatalf("non-existing port count = %d, want 0", count)
	}
}
