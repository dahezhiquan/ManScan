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

func TestAssetDomainRepositoryListReturnsSeverityCounts(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}

	if err := db.AutoMigrate(&entity.AssetDomain{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	title := "Example App"
	region := "internal"
	riskLevel := "high"
	items := []entity.AssetDomain{
		{
			ID:                 1,
			Domain:             "app.example.com:443",
			Title:              &title,
			Region:             &region,
			RiskLevel:          &riskLevel,
			VulnerabilityCount: 6,
			CriticalCount:      1,
			HighCount:          2,
			MediumCount:        2,
			LowCount:           1,
			ComponentCount:     3,
			IsAlive:            true,
		},
		{
			ID:                 2,
			Domain:             "static.example.com:443",
			VulnerabilityCount: 0,
			IsAlive:            false,
		},
	}
	for i := range items {
		if err := db.Create(&items[i]).Error; err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	repo := NewAssetDomainRepository(db)
	page, err := repo.List(context.Background(), dto.ListAssetDomainsQuery{
		Page:         1,
		PageSize:     10,
		Keyword:      "example app",
		Region:       "internal",
		AssetAddress: "app.example.com",
		RiskLevel:    "high",
		IsAlive:      boolPointer(true),
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("page = %+v, want exactly one item", page)
	}

	got := page.Items[0]
	if got.CriticalCount != 1 || got.HighCount != 2 || got.MediumCount != 2 || got.LowCount != 1 {
		t.Fatalf("severity counts = critical:%d high:%d medium:%d low:%d, want 1/2/2/1",
			got.CriticalCount,
			got.HighCount,
			got.MediumCount,
			got.LowCount,
		)
	}
}

func TestAssetDomainRepositorySyncLivenessUpdatesAliveFields(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.AssetDomain{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX uk_asset_domain_domain ON manscan_asset_domain(domain)").Error; err != nil {
		t.Fatalf("Create unique index error = %v", err)
	}

	firstAliveAt := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	lastAliveAt := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	observedAt := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	title := "Existing Title"
	if err := db.Create(&entity.AssetDomain{
		Domain:       "app.example.com:443",
		Title:        &title,
		IsAlive:      false,
		FirstAliveAt: &firstAliveAt,
		LastAliveAt:  &lastAliveAt,
	}).Error; err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := db.Create(&entity.AssetDomain{
		Domain:  "old.example.com:443",
		IsAlive: true,
	}).Error; err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	repo := NewAssetDomainRepository(db)
	if err := repo.SyncLiveness(context.Background(), []string{
		"api.example.com:8443",
		"api.example.com:8443",
		"app.example.com:443",
	}, []string{
		"api.example.com:8443",
		"app.example.com:443",
		"old.example.com:443",
		"missing.example.com:443",
	}, observedAt); err != nil {
		t.Fatalf("SyncLiveness() error = %v", err)
	}

	var items []entity.AssetDomain
	if err := db.Order("domain ASC").Find(&items).Error; err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("domain count = %d, want 3 (%+v)", len(items), items)
	}

	byDomain := make(map[string]entity.AssetDomain, len(items))
	for _, item := range items {
		byDomain[item.Domain] = item
	}
	inserted := byDomain["api.example.com:8443"]
	if !inserted.IsAlive || inserted.FirstAliveAt == nil || !inserted.FirstAliveAt.Equal(observedAt) || inserted.LastAliveAt == nil || !inserted.LastAliveAt.Equal(observedAt) {
		t.Fatalf("inserted liveness = %+v, want alive with observed timestamps", inserted)
	}
	existing := byDomain["app.example.com:443"]
	if !existing.IsAlive || existing.Title == nil || *existing.Title != title {
		t.Fatalf("existing item = %+v, want alive with retained title", existing)
	}
	if existing.FirstAliveAt == nil || !existing.FirstAliveAt.Equal(firstAliveAt) {
		t.Fatalf("existing first_alive_at = %v, want %v", existing.FirstAliveAt, firstAliveAt)
	}
	if existing.LastAliveAt == nil || !existing.LastAliveAt.Equal(observedAt) {
		t.Fatalf("existing last_alive_at = %v, want %v", existing.LastAliveAt, observedAt)
	}
	old := byDomain["old.example.com:443"]
	if old.IsAlive {
		t.Fatalf("old IsAlive = true, want false")
	}
}

func boolPointer(value bool) *bool {
	return &value
}
