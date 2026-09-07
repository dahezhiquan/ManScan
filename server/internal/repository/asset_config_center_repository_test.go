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

func TestAssetConfigCenterRepositoryListFiltersAndPaginates(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}

	if err := db.AutoMigrate(&entity.AssetConfigCenter{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	description := "first"
	items := []entity.AssetConfigCenter{
		{ID: 1, ItemName: "Alpha Config", BigCategory: "app", SmallCategory: "web", Status: "enabled", Description: &description},
		{ID: 2, ItemName: "Beta Config", BigCategory: "app", SmallCategory: "api", Status: "disabled"},
		{ID: 3, ItemName: "Gamma Policy", BigCategory: "security", SmallCategory: "web", Status: "enabled"},
	}
	for i := range items {
		if err := db.Create(&items[i]).Error; err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	repo := NewAssetConfigCenterRepository(db)
	filtered, err := repo.List(context.Background(), dto.ListAssetConfigCentersQuery{
		Page:            1,
		PageSize:        10,
		ItemNames:       []string{"config"},
		BigCategories:   []string{"app"},
		SmallCategories: []string{"web"},
		Statuses:        []string{"enabled"},
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if filtered.Total != 1 || len(filtered.Items) != 1 {
		t.Fatalf("filtered result = %+v, want 1 item", filtered)
	}
	if filtered.Items[0].ItemName != "Alpha Config" {
		t.Fatalf("filtered item name = %q, want Alpha Config", filtered.Items[0].ItemName)
	}

	paged, err := repo.List(context.Background(), dto.ListAssetConfigCentersQuery{
		Page:     2,
		PageSize: 2,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if paged.Total != 3 || paged.TotalPages != 2 || len(paged.Items) != 1 {
		t.Fatalf("paged result = %+v, want total=3 totalPages=2 items=1", paged)
	}
	if paged.Items[0].ItemName != "Gamma Policy" {
		t.Fatalf("paged item name = %q, want Gamma Policy", paged.Items[0].ItemName)
	}
}
