package repository

import (
	"context"
	"strings"
	"testing"

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

func boolPointer(value bool) *bool {
	return &value
}
