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

func TestAssetDomainRepositoryListFiltersAndReturnsItems(t *testing.T) {
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
	items := []entity.AssetDomain{
		{
			ID:      1,
			Domain:  "app.example.com:443",
			Title:   &title,
			Region:  &region,
			IsAlive: true,
		},
		{
			ID:      2,
			Domain:  "static.example.com:443",
			IsAlive: false,
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
		IsAlive:      boolPointer(true),
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("page = %+v, want exactly one item", page)
	}

	if got := page.Items[0]; got.Domain != "app.example.com:443" || !got.IsAlive {
		t.Fatalf("item = %+v, want filtered app domain with alive state", got)
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
	existingStatusCode := uint(418)
	existingRequest := "GET /old HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
	existingResponse := "HTTP/1.1 418 I'm a teapot\r\n\r\nold"
	if err := db.Create(&entity.AssetDomain{
		Domain:         "app.example.com:443",
		Title:          &title,
		HTTPStatusCode: &existingStatusCode,
		Request:        &existingRequest,
		Response:       &existingResponse,
		IsAlive:        false,
		FirstAliveAt:   &firstAliveAt,
		LastAliveAt:    &lastAliveAt,
	}).Error; err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	oldStatusCode := uint(200)
	oldRequest := "GET / HTTP/1.1\r\nHost: old.example.com\r\n\r\n"
	oldResponse := "HTTP/1.1 200 OK\r\n\r\nold"
	if err := db.Create(&entity.AssetDomain{
		Domain:         "old.example.com:443",
		HTTPStatusCode: &oldStatusCode,
		Request:        &oldRequest,
		Response:       &oldResponse,
		IsAlive:        true,
	}).Error; err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	repo := NewAssetDomainRepository(db)
	if err := repo.SyncObservations(context.Background(), []AssetDomainObservation{
		{
			Domain:         "api.example.com:8443",
			Region:         "外网",
			HTTPStatusCode: 201,
			Title:          "API",
			Request:        "GET /api HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			Response:       "HTTP/1.1 201 Created\r\n\r\napi",
		},
		{
			Domain:         "api.example.com:8443",
			HTTPStatusCode: 202,
			Title:          "Duplicate API",
		},
		{
			Domain:         "app.example.com:443",
			Region:         "内网",
			HTTPStatusCode: 302,
			Title:          "Final Title",
			Request:        "GET /final HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			Response:       "HTTP/1.1 200 OK\r\n\r\nfinal",
		},
	}, []string{
		"api.example.com:8443",
		"app.example.com:443",
		"old.example.com:443",
		"missing.example.com:443",
	}, observedAt); err != nil {
		t.Fatalf("SyncObservations() error = %v", err)
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
	if inserted.HTTPStatusCode == nil || *inserted.HTTPStatusCode != 201 || inserted.Title == nil || *inserted.Title != "API" {
		t.Fatalf("inserted observation = %+v, want first observation fields", inserted)
	}
	if inserted.Region == nil || *inserted.Region != "外网" {
		t.Fatalf("inserted region = %v, want 外网", inserted.Region)
	}
	if inserted.Request == nil || *inserted.Request != "GET /api HTTP/1.1\r\nHost: api.example.com\r\n\r\n" {
		t.Fatalf("inserted request = %v, want probe request", inserted.Request)
	}
	if inserted.Response == nil || *inserted.Response != "HTTP/1.1 201 Created\r\n\r\napi" {
		t.Fatalf("inserted response = %v, want probe response", inserted.Response)
	}
	existing := byDomain["app.example.com:443"]
	if !existing.IsAlive || existing.Title == nil || *existing.Title != "Final Title" {
		t.Fatalf("existing item = %+v, want alive with updated title", existing)
	}
	if existing.HTTPStatusCode == nil || *existing.HTTPStatusCode != 302 {
		t.Fatalf("existing HTTPStatusCode = %v, want 302", existing.HTTPStatusCode)
	}
	if existing.Region == nil || *existing.Region != "内网" {
		t.Fatalf("existing region = %v, want 内网", existing.Region)
	}
	if existing.Request == nil || *existing.Request != "GET /final HTTP/1.1\r\nHost: app.example.com\r\n\r\n" {
		t.Fatalf("existing request = %v, want final request", existing.Request)
	}
	if existing.Response == nil || *existing.Response != "HTTP/1.1 200 OK\r\n\r\nfinal" {
		t.Fatalf("existing response = %v, want final response", existing.Response)
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
	if old.HTTPStatusCode == nil || *old.HTTPStatusCode != oldStatusCode || old.Request == nil || *old.Request != oldRequest || old.Response == nil || *old.Response != oldResponse {
		t.Fatalf("old observation = %+v, want retained observation fields", old)
	}
}

func TestAssetDomainRepositorySyncObservationsInsertUsesFieldWhitelist(t *testing.T) {
	t.Parallel()

	statements := make([]string, 0)
	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: sqlCaptureLogger{
			Interface:  logger.Default.LogMode(logger.Silent),
			statements: &statements,
		},
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

	statements = statements[:0]
	repo := NewAssetDomainRepository(db)
	if err := repo.SyncObservations(context.Background(), []AssetDomainObservation{
		{
			Domain:         "api.example.com:8443",
			Region:         "外网",
			HTTPStatusCode: 200,
			Title:          "API",
			Request:        "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			Response:       "HTTP/1.1 200 OK\r\n\r\napi",
		},
	}, []string{"api.example.com:8443"}, time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("SyncObservations() error = %v", err)
	}

	insertSQL := ""
	for _, statement := range statements {
		if strings.Contains(strings.ToLower(statement), "insert into") &&
			strings.Contains(strings.ToLower(statement), "manscan_asset_domain") {
			insertSQL = statement
			break
		}
	}
	if insertSQL == "" {
		t.Fatalf("insert SQL not captured; statements = %v", statements)
	}
	for _, column := range []string{
		"crawler_path_count",
		"whitebox_path_count",
		"vulnerability_count",
		"critical_count",
		"high_count",
		"medium_count",
		"low_count",
		"components",
		"component_count",
	} {
		if strings.Contains(insertSQL, column) {
			t.Fatalf("insert SQL contains unconfirmed count column %q: %s", column, insertSQL)
		}
	}
	for _, column := range []string{
		"domain",
		"is_alive",
		"first_alive_at",
		"last_alive_at",
		"http_status_code",
		"region",
		"title",
		"request",
		"response",
	} {
		if !strings.Contains(insertSQL, column) {
			t.Fatalf("insert SQL missing expected column %q: %s", column, insertSQL)
		}
	}
}

func TestAssetDomainRepositoryListNetworkItems(t *testing.T) {
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

	items := []entity.AssetConfigCenter{
		{ItemName: "10.0.0.0/8", BigCategory: "network", SmallCategory: "生产内网", Status: "enabled"},
		{ItemName: "192.168.0.0/16", BigCategory: "network", SmallCategory: "办公内网", Status: "enabled"},
		{ItemName: "172.16.0.0/12", BigCategory: "network", SmallCategory: "测试内网", Status: "disabled"},
		{ItemName: "203.0.113.0/24", BigCategory: "owner", SmallCategory: "unused", Status: "enabled"},
	}
	for i := range items {
		if err := db.Create(&items[i]).Error; err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	repo := NewAssetDomainRepository(db)
	networkItems, err := repo.ListNetworkItems(context.Background())
	if err != nil {
		t.Fatalf("ListNetworkItems() error = %v", err)
	}
	got := make([]string, 0, len(networkItems))
	for _, item := range networkItems {
		got = append(got, item.ItemName+":"+item.SmallCategory)
	}
	if strings.Join(got, ",") != "10.0.0.0/8:生产内网,192.168.0.0/16:办公内网,172.16.0.0/12:测试内网" {
		t.Fatalf("ListNetworkItems() = %v, want network item_name and small_category only", networkItems)
	}
}

type sqlCaptureLogger struct {
	logger.Interface
	statements *[]string
}

func (l sqlCaptureLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	statement, _ := fc()
	*l.statements = append(*l.statements, statement)
}

func boolPointer(value bool) *bool {
	return &value
}
