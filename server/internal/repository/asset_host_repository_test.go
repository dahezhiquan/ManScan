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
		Keyword:          "10.72.160",
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
		Page:     1,
		PageSize: 10,
		Keyword:  "example.com",
	})
	if err != nil {
		t.Fatalf("List() with related-domain keyword error = %v", err)
	}
	if page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("related-domain keyword page = %+v, want no results because keyword only searches ip_address", page)
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

func TestAssetHostRepositoryDetailReturnsPortsAndFilteredVulnerabilityStats(t *testing.T) {
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
	earlier := now.Add(-time.Hour)
	region := "生产区"
	owner := "安全团队"
	osType := "linux"
	osVersion := "5.15"
	manualNote := "核心主机"
	relatedDomains := "app.example.com"
	host := "10.72.160.123"
	if err := db.Create(&entity.AssetHost{
		IPAddress:      host,
		Region:         &region,
		Owner:          &owner,
		OSType:         &osType,
		OSVersion:      &osVersion,
		ScanCreatedAt:  earlier,
		LastAliveAt:    &now,
		ManualNote:     &manualNote,
		IsAlive:        true,
		RelatedDomains: &relatedDomains,
	}).Error; err != nil {
		t.Fatalf("Create host error = %v", err)
	}

	otherHost := "10.72.160.200"
	if err := db.Create(&[]entity.Vulnerability{
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
			VulnFingerprint:    "detail-host-high",
		},
		{
			TemplateID:         "tpl-unknown",
			VulnerabilityName:  "Unknown Vulnerability",
			LatestScanTaskName: "task",
			LatestScanTaskID:   "1",
			FirstFoundAt:       now,
			LastFoundAt:        now,
			Status:             "confirmed",
			AssetHost:          &host,
			Severity:           "unknown",
			VulnFingerprint:    "detail-host-unknown",
		},
		{
			TemplateID:         "tpl-fixed",
			VulnerabilityName:  "Fixed Vulnerability",
			LatestScanTaskName: "task",
			LatestScanTaskID:   "1",
			FirstFoundAt:       now,
			LastFoundAt:        now,
			Status:             "fixed",
			AssetHost:          &host,
			Severity:           "critical",
			VulnFingerprint:    "detail-host-fixed",
		},
		{
			TemplateID:         "tpl-false-positive",
			VulnerabilityName:  "False Positive Vulnerability",
			LatestScanTaskName: "task",
			LatestScanTaskID:   "1",
			FirstFoundAt:       now,
			LastFoundAt:        now,
			Status:             "false_positive",
			AssetHost:          &host,
			Severity:           "medium",
			VulnFingerprint:    "detail-host-false-positive",
		},
		{
			TemplateID:         "tpl-ignored",
			VulnerabilityName:  "Ignored Vulnerability",
			LatestScanTaskName: "task",
			LatestScanTaskID:   "1",
			FirstFoundAt:       now,
			LastFoundAt:        now,
			Status:             "ignored",
			AssetHost:          &host,
			Severity:           "low",
			VulnFingerprint:    "detail-host-ignored",
		},
		{
			TemplateID:         "tpl-other",
			VulnerabilityName:  "Other Vulnerability",
			LatestScanTaskName: "task",
			LatestScanTaskID:   "1",
			FirstFoundAt:       now,
			LastFoundAt:        now,
			Status:             "unreviewed",
			AssetHost:          &otherHost,
			Severity:           "critical",
			VulnFingerprint:    "detail-host-other",
		},
	}).Error; err != nil {
		t.Fatalf("Create vulnerabilities error = %v", err)
	}

	httpName := "http"
	nginxName := "nginx"
	redisName := "redis"
	nginxVersion := "1.24"
	if err := db.Create(&[]entity.AssetHostPort{
		{
			IPAddress:      host,
			Region:         &region,
			LastAliveAt:    &now,
			PortCreatedAt:  earlier,
			PortProtocol:   "tcp",
			PortNumber:     8080,
			ServiceName:    &httpName,
			AppName:        &nginxName,
			AppVersion:     &nginxVersion,
			IsAlive:        true,
			IsHighRiskPort: false,
		},
		{
			IPAddress:      host,
			Region:         &region,
			LastAliveAt:    &earlier,
			PortCreatedAt:  earlier,
			PortProtocol:   "tcp",
			PortNumber:     6379,
			ServiceName:    &redisName,
			AppName:        &redisName,
			IsAlive:        false,
			IsHighRiskPort: true,
		},
		{
			IPAddress:     otherHost,
			PortCreatedAt: earlier,
			PortProtocol:  "tcp",
			PortNumber:    80,
			IsAlive:       true,
		},
	}).Error; err != nil {
		t.Fatalf("Create host ports error = %v", err)
	}

	repo := NewAssetHostRepository(db)
	detail, err := repo.Detail(context.Background(), " 10.72.160.123 ")
	if err != nil {
		t.Fatalf("Detail() error = %v", err)
	}

	if detail.IPAddress != host || detail.Region == nil || *detail.Region != region || detail.Owner == nil || *detail.Owner != owner {
		t.Fatalf("detail host = %+v, want saved host metadata", detail.AssetHost)
	}
	if detail.VulnerabilityCount != 2 || detail.HighCount != 1 || detail.CriticalCount != 0 || detail.MediumCount != 0 || detail.LowCount != 0 {
		t.Fatalf(
			"detail vuln counts = vulnerability:%d critical:%d high:%d medium:%d low:%d, want filtered vulnerability:2 critical:0 high:1 medium:0 low:0",
			detail.VulnerabilityCount,
			detail.CriticalCount,
			detail.HighCount,
			detail.MediumCount,
			detail.LowCount,
		)
	}
	if len(detail.Ports) != 2 {
		t.Fatalf("ports = %+v, want two ports for requested host", detail.Ports)
	}
	if detail.Ports[0].PortNumber != 8080 || !detail.Ports[0].IsAlive || detail.Ports[0].ServiceName == nil || *detail.Ports[0].ServiceName != "http" {
		t.Fatalf("first port = %+v, want alive http 8080 first", detail.Ports[0])
	}
	if detail.Ports[1].PortNumber != 6379 || !detail.Ports[1].IsHighRiskPort {
		t.Fatalf("second port = %+v, want high-risk redis 6379", detail.Ports[1])
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
