package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestAssetHostRepositoryListFiltersAndReturnsItems(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}

	if err := db.AutoMigrate(&entity.AssetHost{}, &entity.Vulnerability{}, &entity.AssetHostPort{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	region := "生产区"
	owner := "安全团队"
	linux := "linux"
	windows := "windows"
	relatedDomains := "app.example.com"
	if err := db.Create(&[]entity.AssetHost{
		{
			ID:             1,
			IPAddress:      "10.72.160.123",
			Region:         &region,
			Owner:          &owner,
			OSType:         &linux,
			ScanCreatedAt:  now,
			LastAliveAt:    &now,
			IsAlive:        true,
			RelatedDomains: &relatedDomains,
		},
		{
			ID:            2,
			IPAddress:     "10.72.160.200",
			OSType:        &windows,
			ScanCreatedAt: now,
			IsAlive:       false,
		},
	}).Error; err != nil {
		t.Fatalf("Create hosts error = %v", err)
	}

	host := "10.72.160.123"
	if err := db.Create(&[]entity.Vulnerability{
		{
			TemplateID:         "tpl-critical",
			VulnerabilityName:  "Critical Vulnerability",
			LatestScanTaskName: "task",
			LatestScanTaskID:   "1",
			FirstFoundAt:       now,
			LastFoundAt:        now,
			Status:             "unreviewed",
			AssetHost:          &host,
			Severity:           "critical",
			VulnFingerprint:    "host-fingerprint-critical",
		},
		{
			TemplateID:         "tpl-high",
			VulnerabilityName:  "High Vulnerability",
			LatestScanTaskName: "task",
			LatestScanTaskID:   "1",
			FirstFoundAt:       now,
			LastFoundAt:        now,
			Status:             "unreviewed",
			AssetHost:          &host,
			Severity:           "high",
			VulnFingerprint:    "host-fingerprint-high",
		},
	}).Error; err != nil {
		t.Fatalf("Create vulnerabilities error = %v", err)
	}
	if err := db.Create(&[]entity.AssetHostPort{
		{
			IPAddress:     host,
			Region:        &region,
			LastAliveAt:   &now,
			PortCreatedAt: now,
			PortProtocol:  "tcp",
			PortNumber:    80,
			IsAlive:       true,
		},
		{
			IPAddress:     host,
			Region:        &region,
			LastAliveAt:   &now,
			PortCreatedAt: now,
			PortProtocol:  "tcp",
			PortNumber:    8080,
			IsAlive:       false,
		},
	}).Error; err != nil {
		t.Fatalf("Create host ports error = %v", err)
	}

	repo := NewAssetHostRepository(db)
	page, err := repo.List(context.Background(), dto.ListAssetHostsQuery{
		Page:             1,
		PageSize:         10,
		Keyword:          "example",
		Owner:            "安全",
		OSType:           "lin",
		Region:           "生产",
		AssetAddress:     "10.72.160",
		RiskLevels:       []string{"critical"},
		HasVulnerability: boolPointer(true),
		HasPort:          boolPointer(true),
		IsAlive:          boolPointer(true),
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("page = %+v, want exactly one item", page)
	}
	got := page.Items[0]
	if got.IPAddress != host || got.VulnerabilityCount != 2 || got.CriticalCount != 1 || got.HighCount != 1 || got.PortCount != 1 {
		t.Fatalf("item = %+v, want host counts with one alive port", got)
	}

	page, err = repo.List(context.Background(), dto.ListAssetHostsQuery{
		Page:             1,
		PageSize:         10,
		RiskLevels:       []string{"info"},
		HasVulnerability: boolPointer(false),
		HasPort:          boolPointer(false),
	})
	if err != nil {
		t.Fatalf("List() with empty filters error = %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].IPAddress != "10.72.160.200" {
		t.Fatalf("empty risk filtered page = %+v, want host without vulnerabilities or ports", page)
	}
}

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
