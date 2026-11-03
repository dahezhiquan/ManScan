package repository

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestAssetDomainEachFilteredIncludesAllMatchesAndDetails(t *testing.T) {
	db := openAssetExportTestDB(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	owner := "team"
	for _, item := range []entity.AssetDomain{
		{Domain: "new.example", Owner: &owner, LastAliveAt: &now, IsAlive: true},
		{Domain: "old.example", Owner: &owner, IsAlive: true},
		{Domain: "other.example", IsAlive: true},
	} {
		if err := db.Create(&item).Error; err != nil {
			t.Fatalf("Create domain: %v", err)
		}
	}
	for _, item := range []entity.AssetDomainServiceAsset{
		{Domain: "new.example", AppName: "nginx", FirstFoundAt: now, LastFoundAt: now, IsAlive: true},
		{Domain: "old.example", AppName: "Apache", FirstFoundAt: now, LastFoundAt: now, IsAlive: false},
	} {
		if err := db.Create(&item).Error; err != nil {
			t.Fatalf("Create service asset: %v", err)
		}
	}
	if err := db.Create(&entity.AssetDomainTitleHistory{Domain: "new.example", HistoryTitle: "Portal", FirstTitleCreatedAt: now, LatestTitleAliveAt: now}).Error; err != nil {
		t.Fatalf("Create title history: %v", err)
	}
	repo := NewAssetDomainRepository(db)
	query := dto.ListAssetDomainsQuery{Page: 2, PageSize: 1, Owner: "team"}
	page, err := repo.List(context.Background(), query)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	var exported []AssetDomainExportRecord
	if err := repo.EachFiltered(context.Background(), query, func(item AssetDomainExportRecord) error {
		exported = append(exported, item)
		return nil
	}); err != nil {
		t.Fatalf("EachFiltered() error = %v", err)
	}
	if len(exported) != 2 || exported[0].List.Domain != "new.example" || exported[1].List.Domain != page.Items[0].Domain {
		t.Fatalf("exported domains = %+v", exported)
	}
	if len(exported[0].ServiceAssets) != 1 || exported[0].ServiceAssets[0].AppName != "nginx" || len(exported[0].TitleHistories) != 1 {
		t.Fatalf("new domain details = %+v", exported[0])
	}
	if len(exported[1].ServiceAssets) != 1 || exported[1].ServiceAssets[0].IsAlive {
		t.Fatalf("old domain details = %+v", exported[1])
	}
}

func TestAssetHostEachFilteredIncludesAllMatchesAndPorts(t *testing.T) {
	db := openAssetExportTestDB(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, item := range []entity.AssetHost{
		{IPAddress: "192.0.2.1", ScanCreatedAt: now, LastAliveAt: &now, IsAlive: true},
		{IPAddress: "192.0.2.2", ScanCreatedAt: now, IsAlive: true},
		{IPAddress: "192.0.2.3", ScanCreatedAt: now, IsAlive: true},
	} {
		if err := db.Create(&item).Error; err != nil {
			t.Fatalf("Create host: %v", err)
		}
	}
	for _, item := range []entity.AssetHostPort{
		{IPAddress: "192.0.2.1", PortProtocol: "tcp", PortNumber: 443, PortCreatedAt: now, IsAlive: true},
		{IPAddress: "192.0.2.1", PortProtocol: "tcp", PortNumber: 80, PortCreatedAt: now, IsAlive: false},
		{IPAddress: "192.0.2.2", PortProtocol: "tcp", PortNumber: 22, PortCreatedAt: now, IsAlive: true},
	} {
		if err := db.Create(&item).Error; err != nil {
			t.Fatalf("Create port: %v", err)
		}
	}
	hasPort := true
	repo := NewAssetHostRepository(db)
	query := dto.ListAssetHostsQuery{Page: 2, PageSize: 1, HasPort: &hasPort}
	page, err := repo.List(context.Background(), query)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	var exported []AssetHostExportRecord
	if err := repo.EachFiltered(context.Background(), query, func(item AssetHostExportRecord) error {
		exported = append(exported, item)
		return nil
	}); err != nil {
		t.Fatalf("EachFiltered() error = %v", err)
	}
	if len(exported) != 2 || exported[0].List.IPAddress != "192.0.2.1" || exported[1].List.IPAddress != page.Items[0].IPAddress {
		t.Fatalf("exported hosts = %+v", exported)
	}
	if exported[0].List.PortCount != 1 || len(exported[0].Ports) != 2 || !exported[0].Ports[0].IsAlive || exported[0].Ports[1].IsAlive {
		t.Fatalf("first host ports = %+v", exported[0])
	}
}

func TestAssetExportsContinueAcrossBatchBoundary(t *testing.T) {
	db := openAssetExportTestDB(t)
	domains := make([]entity.AssetDomain, assetExportBatchSize+1)
	hosts := make([]entity.AssetHost, assetExportBatchSize+1)
	for index := range domains {
		domains[index].Domain = fmt.Sprintf("asset-%03d.example", index)
		hosts[index].IPAddress = fmt.Sprintf("192.0.2.%d", index+1)
	}
	if err := db.Create(&domains).Error; err != nil {
		t.Fatalf("Create domains: %v", err)
	}
	if err := db.Create(&hosts).Error; err != nil {
		t.Fatalf("Create hosts: %v", err)
	}
	count := 0
	if err := NewAssetDomainRepository(db).EachFiltered(context.Background(), dto.ListAssetDomainsQuery{}, func(AssetDomainExportRecord) error {
		count++
		return nil
	}); err != nil || count != len(domains) {
		t.Fatalf("domain export count = %d, error = %v", count, err)
	}
	count = 0
	if err := NewAssetHostRepository(db).EachFiltered(context.Background(), dto.ListAssetHostsQuery{}, func(AssetHostExportRecord) error {
		count++
		return nil
	}); err != nil || count != len(hosts) {
		t.Fatalf("host export count = %d, error = %v", count, err)
	}
}

func openAssetExportTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(
		&entity.AssetDomain{}, &entity.AssetDomainServiceAsset{}, &entity.AssetDomainTitleHistory{},
		&entity.AssetHost{}, &entity.AssetHostPort{}, &entity.Vulnerability{},
	); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	return db
}
