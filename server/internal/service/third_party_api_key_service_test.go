package service_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/secretbox"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestThirdPartyAPIKeyServiceEncryptsKeyAndHidesItFromResponses(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.ThirdPartyAPIKey{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	box, err := secretbox.New("a sufficiently long API key encryption secret")
	if err != nil {
		t.Fatalf("secretbox.New() error = %v", err)
	}
	svc := service.NewThirdPartyAPIKeyService(repository.NewThirdPartyAPIKeyRepository(db), box)

	created, err := svc.Create(context.Background(), dto.CreateThirdPartyAPIKeyRequest{
		Key:         "plain-api-key",
		PlatformURL: "https://api.example.com",
		Description: "test provider",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !created.KeyConfigured || created.PlatformURL != "https://api.example.com" {
		t.Fatalf("created response = %+v, want configured key metadata", created)
	}
	responseJSON, err := json.Marshal(created)
	if err != nil {
		t.Fatalf("json.Marshal(created) error = %v", err)
	}
	if strings.Contains(string(responseJSON), "plain-api-key") || strings.Contains(string(responseJSON), "api_key") {
		t.Fatalf("created response JSON contains sensitive key data: %s", responseJSON)
	}

	var stored entity.ThirdPartyAPIKey
	if err := db.First(&stored, created.ID).Error; err != nil {
		t.Fatalf("First() error = %v", err)
	}
	if stored.EncryptedKey == "plain-api-key" || stored.EncryptedKey == "" {
		t.Fatalf("stored key = %q, want non-plaintext ciphertext", stored.EncryptedKey)
	}
	decrypted, err := box.Decrypt(stored.EncryptedKey)
	if err != nil || decrypted != "plain-api-key" {
		t.Fatalf("Decrypt(stored key) = %q, %v; want original key", decrypted, err)
	}

	updated, err := svc.Update(context.Background(), created.ID, dto.UpdateThirdPartyAPIKeyRequest{
		PlatformURL: "https://api.example.com/v2",
		Description: "updated provider",
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if !updated.KeyConfigured || updated.PlatformURL != "https://api.example.com/v2" {
		t.Fatalf("updated response = %+v, want retained key metadata", updated)
	}
	if err := db.First(&stored, created.ID).Error; err != nil {
		t.Fatalf("First() after update error = %v", err)
	}
	if decrypted, err := box.Decrypt(stored.EncryptedKey); err != nil || decrypted != "plain-api-key" {
		t.Fatalf("key after metadata-only update = %q, %v; want original key", decrypted, err)
	}

	listed, err := svc.List(context.Background(), dto.ListThirdPartyAPIKeysQuery{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(listed.Items) != 1 || !listed.Items[0].KeyConfigured {
		t.Fatalf("listed items = %+v, want one item with configured key", listed.Items)
	}
	got, err := svc.Get(context.Background(), created.ID)
	if err != nil || !got.KeyConfigured {
		t.Fatalf("Get() = %+v, %v; want key metadata", got, err)
	}
	plaintext, err := svc.GetPlaintext(context.Background(), created.ID)
	if err != nil || plaintext.Key != "plain-api-key" {
		t.Fatalf("GetPlaintext() = %+v, %v; want original key", plaintext, err)
	}
	// 最长允许的明文必须可往返解密，且密文可放入数据库列。
	longKey := strings.Repeat("k", 512)
	if _, err := svc.Update(context.Background(), created.ID, dto.UpdateThirdPartyAPIKeyRequest{
		Key: &longKey, PlatformURL: "https://api.example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.First(&stored, created.ID).Error; err != nil {
		t.Fatal(err)
	}
	if len(stored.EncryptedKey) > 1024 {
		t.Fatal("ciphertext exceeds the database column size")
	}
	if decrypted, err := box.Decrypt(stored.EncryptedKey); err != nil || decrypted != longKey {
		t.Fatalf("maximum length key failed to round trip: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.Get(ctx, created.ID); err == nil {
		t.Fatal("canceled context must prevent database lookup")
	}
}
