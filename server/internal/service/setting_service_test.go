package service

import (
	"context"
	"errors"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestSettingServiceGetThemeReturnsDefaultWhenMissing(t *testing.T) {
	service := newSettingServiceForTest(t)

	setting, err := service.GetTheme(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetTheme() error = %v", err)
	}
	if setting.Theme != "cartoon" || setting.DarkModeEnabled {
		t.Fatalf("GetTheme() = %+v, want default cartoon with dark mode disabled", setting)
	}
}

func TestSettingServiceUpdateThemePersistsCurrentUserSetting(t *testing.T) {
	service := newSettingServiceForTest(t)
	ctx := context.Background()

	updated, err := service.UpdateTheme(ctx, 1, dto.UpdateThemeSettingRequest{
		Theme:           "Cartoon_Dark",
		DarkModeEnabled: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("UpdateTheme() error = %v", err)
	}
	if updated.Theme != "cartoon_dark" || !updated.DarkModeEnabled {
		t.Fatalf("UpdateTheme() = %+v, want normalized cartoon_dark with dark mode enabled", updated)
	}

	got, err := service.GetTheme(ctx, 1)
	if err != nil {
		t.Fatalf("GetTheme() after update error = %v", err)
	}
	if got.Theme != "cartoon_dark" || !got.DarkModeEnabled {
		t.Fatalf("GetTheme() after update = %+v, want persisted setting", got)
	}

	other, err := service.GetTheme(ctx, 2)
	if err != nil {
		t.Fatalf("GetTheme() for other user error = %v", err)
	}
	if other.Theme != "cartoon" || other.DarkModeEnabled {
		t.Fatalf("GetTheme() for other user = %+v, want isolated default setting", other)
	}
}

func TestSettingServiceRejectsInvalidTheme(t *testing.T) {
	service := newSettingServiceForTest(t)

	_, err := service.UpdateTheme(context.Background(), 1, dto.UpdateThemeSettingRequest{
		Theme:           "<script>",
		DarkModeEnabled: boolPtr(true),
	})
	if !errors.Is(err, ErrInvalidThemeSetting) {
		t.Fatalf("UpdateTheme() error = %v, want ErrInvalidThemeSetting", err)
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func newSettingServiceForTest(t *testing.T) SettingService {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.UserSetting{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})

	return NewSettingService(repository.NewUserSettingRepository(db))
}
