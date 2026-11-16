package repository

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestFindAIForceSelectsUniquePlatformRecord(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "api_keys.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&entity.ThirdPartyAPIKey{}); err != nil {
		t.Fatal(err)
	}
	repo := NewThirdPartyAPIKeyRepository(db)
	ctx := context.Background()
	if _, err := repo.FindAIForce(ctx); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("missing platform error = %v, want record not found", err)
	}
	for _, platform := range []string{"https://example.com/", "https://ai-force.duxiaoman-int.com/", "https://AI-force.duxiaoman-int.com/"} {
		if err := repo.Create(ctx, &entity.ThirdPartyAPIKey{PlatformURL: platform, EncryptedKey: "ciphertext"}); err != nil {
			t.Fatal(err)
		}
	}
	item, err := repo.FindAIForce(ctx)
	if err != nil || item.PlatformURL != "https://ai-force.duxiaoman-int.com/" {
		t.Fatalf("selected item = %+v, error = %v", item, err)
	}
	if err := repo.Create(ctx, &entity.ThirdPartyAPIKey{PlatformURL: "https://ai-force.duxiaoman-int.com", EncryptedKey: "other"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindAIForce(ctx); err == nil {
		t.Fatal("accepted two AI Force key records")
	}
}
