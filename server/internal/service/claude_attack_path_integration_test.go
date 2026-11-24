package service

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ManScan/server/config"
	"ManScan/server/internal/pkg/secretbox"
	"ManScan/server/internal/repository"
	mysqldriver "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Explicitly opt in: reads the configured database key and calls the real AI Force model.
func TestClaudeAttackPathProcessorAIForce(t *testing.T) {
	cfg, gateway := configuredAttackPathTestGateway(t)
	server := httptest.NewServer(gateway)
	defer server.Close()
	processor, err := NewClaudeAttackPathProcessor(cfg.AI.ClaudeBinary, server.URL, gateway.localKey, cfg.AI.Model, cfg.PromptFilePath())
	if err != nil {
		t.Fatalf("cannot configure Claude processor: %v", err)
	}
	output, err := os.CreateTemp(t.TempDir(), "normal-api-paths-")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	processed, kept, err := processor.Process(ctx, strings.NewReader("/api/users\n/../../etc/passwd\n/api/orders\n"), output, 3, nil)
	if err != nil {
		t.Fatalf("real Claude file workflow failed: %v", err)
	}
	result, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	if processed != 3 || kept != 2 || string(result) != "/api/users\n/api/orders\n" {
		t.Fatalf("unexpected real model result: processed=%d kept=%d output=%q", processed, kept, result)
	}
}

func configuredAttackPathTestGateway(t *testing.T) (*config.Config, *AIForceClaudeGateway) {
	t.Helper()
	if os.Getenv("MANSCAN_TEST_AI_FORCE") != "1" {
		t.Skip("real AI Force integration is opt-in")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal("cannot load local server configuration")
	}
	connection, err := mysqldriver.ParseDSN(cfg.MySQL.DSN())
	if err != nil {
		t.Fatal("invalid database configuration")
	}
	connection.Timeout = 5 * time.Second
	connection.ReadTimeout = 10 * time.Second
	connection.WriteTimeout = 10 * time.Second
	db, err := gorm.Open(mysql.Open(connection.FormatDSN()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal("cannot connect to configured key database")
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal("cannot access database connection")
	}
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Error("cannot close integration database")
		}
	})
	box, err := secretbox.New(cfg.Auth.APIKeyEncryptionKey)
	if err != nil {
		t.Fatal("invalid key encryption configuration")
	}
	key, err := randomAttackPathID()
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewAIForceClaudeGateway(cfg.AI.Model, cfg.AI.UUAPID, key, repository.NewThirdPartyAPIKeyRepository(db), box)
	if err != nil {
		t.Fatal("invalid AI Force gateway configuration")
	}
	return cfg, gateway
}
