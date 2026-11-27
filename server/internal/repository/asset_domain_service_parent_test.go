package repository

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestCreateMissingAssetDomainsMySQLConflictClause(t *testing.T) {
	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN: "user:pass@tcp(127.0.0.1:3306)/test", SkipInitializeWithVersion: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
	if err != nil {
		t.Fatal(err)
	}
	var statement string
	if err := db.Callback().Create().After("gorm:create").Register("capture_parent_insert", func(tx *gorm.DB) {
		statement = tx.Statement.SQL.String()
	}); err != nil {
		t.Fatal(err)
	}
	if err := createMissingAssetDomains(context.Background(), db, []AssetDomainObservation{
		{Domain: "sip.example.com:5060", Title: "非 HTTP 服务"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statement, "ON DUPLICATE KEY UPDATE `domain`=domain") {
		t.Fatalf("invalid MySQL conflict clause: %s", statement)
	}
}

func TestAssetDomainRepositorySyncServiceAssetsCreatesMissingParents(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&entity.AssetDomain{}, &entity.AssetDomainServiceAsset{}); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		"CREATE UNIQUE INDEX uk_domain ON manscan_asset_domain(domain)",
		"CREATE UNIQUE INDEX uk_domain_app ON manscan_asset_domain_service_assets(domain, app_name)",
	} {
		if err := db.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	oldTime := time.Date(2026, 11, 20, 1, 0, 0, 0, time.UTC)
	existing := entity.AssetDomain{
		Domain: "web.example.com:5060", Title: assetDomainTestPtr("Portal"),
		HTTPStatusCode: assetDomainTestPtr(uint(200)), Request: assetDomainTestPtr("GET /"), Response: assetDomainTestPtr("HTTP/1.1 200 OK"),
		Owner: assetDomainTestPtr("owner"), ManualNote: assetDomainTestPtr("keep"),
		FirstAliveAt: &oldTime, LastAliveAt: &oldTime, IsAlive: true,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatal(err)
	}
	var before entity.AssetDomain
	if err := db.First(&before, existing.ID).Error; err != nil {
		t.Fatal(err)
	}
	const endpoint = "rjy-f3l-vcse.duxiaoman.com:5060"
	observedAt := oldTime.Add(time.Hour)
	repo := NewAssetDomainRepository(db)
	components := []AssetDomainServiceAssetObservation{
		{Domain: endpoint, AppName: "sip"}, {Domain: existing.Domain, AppName: "sip"},
	}
	parents := []AssetDomainObservation{
		{Domain: endpoint, Title: "非 HTTP 服务", Region: "external"},
		{Domain: endpoint, Title: "非 HTTP 服务", Region: "external"},
		{Domain: existing.Domain, Title: "非 HTTP 服务"},
	}
	for i := 0; i < 2; i++ {
		if err := repo.SyncServiceAssets(context.Background(), components, nil, parents, observedAt.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	var assets []entity.AssetDomain
	if err := db.Order("id").Find(&assets).Error; err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 {
		t.Fatalf("assets = %+v, want two distinct endpoints", assets)
	}
	if !reflect.DeepEqual(before, assets[0]) {
		t.Fatalf("existing asset changed: before=%+v after=%+v", before, assets[0])
	}
	parent := assets[1]
	if parent.Domain != endpoint || parent.Title == nil || *parent.Title != "非 HTTP 服务" || !parent.IsAlive || parent.Region == nil || *parent.Region != "external" {
		t.Fatalf("parent = %+v", parent)
	}
	if parent.HTTPStatusCode != nil || parent.Request != nil || parent.Response != nil {
		t.Fatalf("unexpected HTTP data: %+v", parent)
	}
	if parent.FirstAliveAt == nil || !parent.FirstAliveAt.Equal(observedAt) || parent.LastAliveAt == nil || !parent.LastAliveAt.Equal(observedAt) {
		t.Fatalf("parent timestamps = %+v", parent)
	}
	var count int64
	if err := db.Table("manscan_asset_domain_service_assets AS s").Joins("JOIN manscan_asset_domain AS a ON a.domain = s.domain").Where("a.domain = ? AND s.app_name = ?", endpoint, "sip").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("joined SIP components = %d, want 1", count)
	}
}

func TestAssetDomainRepositorySyncServiceAssetsRollsBackMissingParent(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately omit the component table to fail after the parent insert.
	if err := db.AutoMigrate(&entity.AssetDomain{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX uk_domain ON manscan_asset_domain(domain)").Error; err != nil {
		t.Fatal(err)
	}
	err = NewAssetDomainRepository(db).SyncServiceAssets(context.Background(),
		[]AssetDomainServiceAssetObservation{{Domain: "sip.example.com:5060", AppName: "sip"}}, nil,
		[]AssetDomainObservation{{Domain: "sip.example.com:5060", Title: "非 HTTP 服务"}}, time.Now())
	if err == nil {
		t.Fatal("expected component insertion failure")
	}
	var count int64
	if err := db.Model(&entity.AssetDomain{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("parent count after rollback = %d", count)
	}
}
