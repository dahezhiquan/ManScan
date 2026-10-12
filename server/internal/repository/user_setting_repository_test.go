package repository

import (
	"context"
	"path/filepath"
	"testing"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestUserSettingRepositoryUpsertTheme(t *testing.T) {
	db := newUserSettingRepositoryTestDB(t)
	repo := NewUserSettingRepository(db)
	ctx := context.Background()

	if err := repo.UpsertTheme(ctx, &entity.UserSetting{
		UserID:          1,
		Theme:           "cartoon",
		DarkModeEnabled: false,
	}); err != nil {
		t.Fatalf("UpsertTheme() create error = %v", err)
	}

	setting, err := repo.FindByUserID(ctx, 1)
	if err != nil {
		t.Fatalf("FindByUserID() error = %v", err)
	}
	if setting.Theme != "cartoon" || setting.DarkModeEnabled {
		t.Fatalf("FindByUserID() = %+v, want cartoon and dark_mode_enabled=false", setting)
	}

	if err := repo.UpsertTheme(ctx, &entity.UserSetting{
		UserID:          1,
		Theme:           "classic_dark",
		DarkModeEnabled: true,
	}); err != nil {
		t.Fatalf("UpsertTheme() update error = %v", err)
	}

	setting, err = repo.FindByUserID(ctx, 1)
	if err != nil {
		t.Fatalf("FindByUserID() after update error = %v", err)
	}
	if setting.Theme != "classic_dark" || !setting.DarkModeEnabled {
		t.Fatalf("FindByUserID() after update = %+v, want classic_dark and dark_mode_enabled=true", setting)
	}
}

func newUserSettingRepositoryTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "settings.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.UserSetting{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	return db
}
