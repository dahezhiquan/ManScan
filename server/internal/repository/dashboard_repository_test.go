package repository

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openDashboardTestDB(testingContext testing.TB) *gorm.DB {
	testingContext.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		testingContext.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		testingContext.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	testingContext.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			testingContext.Error(err)
		}
	})
	if err := db.AutoMigrate(&entity.Vulnerability{}, &entity.AssetHost{}, &entity.AssetDomain{}, &entity.AssetHostPort{}, &entity.AssetDomainServiceAsset{}); err != nil {
		testingContext.Fatal(err)
	}
	return db
}

func createDashboardRows(testingContext testing.TB, db *gorm.DB, rows interface{}) {
	testingContext.Helper()
	if err := db.CreateInBatches(rows, 200).Error; err != nil {
		testingContext.Fatal(err)
	}
}

func dashboardString(value string) *string {
	return &value
}

func TestDashboardRepositoryAssetRiskCounts(t *testing.T) {
	t.Parallel()
	db := openDashboardTestDB(t)
	hosts := make([]entity.AssetHost, 0, 8)
	domains := make([]entity.AssetDomain, 0, 8)
	vulnerabilities := make([]entity.Vulnerability, 0, 11)
	for index, severity := range []string{"critical", "HIGH", "medium", "low", "info", "unknown", "critical", ""} {
		host := fmt.Sprintf("10.0.0.%d", index+1)
		domain := fmt.Sprintf("app%d.example.com:443", index+1)
		hosts = append(hosts, entity.AssetHost{IPAddress: host})
		domains = append(domains, entity.AssetDomain{Domain: domain})
		if severity == "" {
			continue
		}
		status := "unreviewed"
		if index == 6 {
			status = "fixed"
		}
		vulnerabilities = append(vulnerabilities, entity.Vulnerability{AssetHost: dashboardString(host), AssetEndpoint: dashboardString(domain), Severity: severity, Status: status})
	}
	vulnerabilities = append(vulnerabilities,
		entity.Vulnerability{AssetHost: dashboardString(hosts[0].IPAddress), AssetEndpoint: dashboardString(domains[0].Domain), Severity: "high", Status: "confirmed"},
		entity.Vulnerability{AssetHost: dashboardString(hosts[2].IPAddress), AssetEndpoint: dashboardString(domains[2].Domain), Severity: "critical", Status: "false_positive"},
		entity.Vulnerability{AssetHost: dashboardString(hosts[3].IPAddress), AssetEndpoint: dashboardString(domains[3].Domain), Severity: "critical", Status: "IGNORED"},
		entity.Vulnerability{AssetHost: dashboardString("orphan"), AssetEndpoint: dashboardString("orphan:443"), Severity: "critical", Status: "unreviewed"},
	)
	createDashboardRows(t, db, &hosts)
	createDashboardRows(t, db, &domains)
	createDashboardRows(t, db, &vulnerabilities)
	repo := NewDashboardRepository(db)
	want := entity.DashboardAssetRiskCount{Critical: 1, High: 1, Medium: 1, Low: 1, NoRisk: 2, Unknown: 2}
	for name, query := range map[string]func(context.Context) (entity.DashboardAssetRiskCount, error){
		"hosts": repo.FindHostRiskCounts, "domains": repo.FindDomainRiskCounts,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := query(context.Background())
			if err != nil || got != want {
				t.Fatalf("counts = %+v, error = %v, want %+v", got, err, want)
			}
		})
	}
}

func TestDashboardRepositoryVulnerabilityCountsAndHighRiskPorts(t *testing.T) {
	t.Parallel()
	db := openDashboardTestDB(t)
	createDashboardRows(t, db, &[]entity.Vulnerability{
		{Status: "unreviewed", Severity: "critical"}, {Status: "UNREVIEWED", Severity: "CRITICAL"},
		{Status: "confirmed", Severity: "high"}, {Status: "ticketed", Severity: "medium"},
		{Status: "fixed", Severity: "low"}, {Status: "false_positive", Severity: "info"}, {Status: "ignored", Severity: "unknown"},
	})
	createDashboardRows(t, db, &[]entity.AssetHostPort{
		{IsAlive: true, IsHighRiskPort: assetDomainTestPtr(true)}, {IsAlive: true, IsHighRiskPort: assetDomainTestPtr(true)},
		{IsAlive: true, IsHighRiskPort: assetDomainTestPtr(false)}, {IsAlive: false, IsHighRiskPort: assetDomainTestPtr(true)},
	})
	repo := NewDashboardRepository(db)
	counts, err := repo.ListVulnerabilityCounts(context.Background())
	if err != nil || len(counts) != 6 {
		t.Fatalf("counts = %+v, error = %v, want 6 groups", counts, err)
	}
	var total, pending int64
	for _, count := range counts {
		total += count.Count
		if count.Status == "unreviewed" && count.Severity == "critical" {
			pending = count.Count
		}
	}
	if total != 7 || pending != 2 {
		t.Fatalf("total/pending = %d/%d, want 7/2", total, pending)
	}
	ports, err := repo.CountHighRiskOpenPorts(context.Background())
	if err != nil || ports != 2 {
		t.Fatalf("ports = %d, error = %v, want 2", ports, err)
	}
}

func TestDashboardRepositoryRankingsLimitAndFilters(t *testing.T) {
	t.Parallel()
	db := openDashboardTestDB(t)
	for index := 1; index <= 12; index++ {
		host := fmt.Sprintf("10.0.0.%02d", index)
		createDashboardRows(t, db, &entity.AssetHost{IPAddress: host})
		createDashboardRows(t, db, &entity.Vulnerability{AssetHost: &host, Status: "fixed"})
		createDashboardRows(t, db, &entity.AssetHostPort{IPAddress: host, IsAlive: true, ServiceName: dashboardString(fmt.Sprintf("service%02d", index))})
		createDashboardRows(t, db, &entity.AssetDomainServiceAsset{Domain: host + ":443", AppName: fmt.Sprintf("app%02d", index), IsAlive: true})
	}
	createDashboardRows(t, db, &entity.Vulnerability{AssetHost: dashboardString("not-a-host.example.com"), Status: "unreviewed"})
	createDashboardRows(t, db, &[]entity.AssetHostPort{
		{IPAddress: "10.0.0.01", IsAlive: false, ServiceName: dashboardString("service01")},
		{IsAlive: true, ServiceName: nil}, {IsAlive: true, ServiceName: dashboardString("  ")},
		{IPAddress: "orphan", IsAlive: false, ServiceName: dashboardString("orphan")},
	})
	createDashboardRows(t, db, &[]entity.AssetDomainServiceAsset{
		{Domain: "dead:443", AppName: "app01", IsAlive: false}, {Domain: "empty:443", AppName: " ", IsAlive: true},
	})
	repo := NewDashboardRepository(db)
	for name, query := range map[string]func(context.Context) ([]entity.DashboardHostCount, error){
		"vulnerabilities": repo.ListTopHostVulnerabilities, "ports": repo.ListTopHostPorts,
	} {
		t.Run(name, func(t *testing.T) {
			counts, err := query(context.Background())
			if err != nil || len(counts) != 10 || counts[0].IPAddress != "10.0.0.01" || counts[9].IPAddress != "10.0.0.10" || counts[0].Count != 1 {
				t.Fatalf("counts = %+v, error = %v", counts, err)
			}
		})
	}
	for name, query := range map[string]func(context.Context) ([]entity.DashboardFingerprintCount, error){
		"apps": repo.ListTopDomainFingerprints, "services": repo.ListTopHostFingerprints,
	} {
		t.Run(name, func(t *testing.T) {
			counts, err := query(context.Background())
			if err != nil || len(counts) != 10 || counts[0].Count != 1 {
				t.Fatalf("counts = %+v, error = %v", counts, err)
			}
		})
	}
	createDashboardRows(t, db, &entity.Vulnerability{AssetHost: dashboardString("10.0.0.12")})
	createDashboardRows(t, db, &entity.AssetHostPort{IPAddress: "10.0.0.12", IsAlive: true, ServiceName: dashboardString("service12")})
	createDashboardRows(t, db, &entity.AssetDomainServiceAsset{Domain: "second:443", AppName: "app12", IsAlive: true})
	for _, query := range []func(context.Context) ([]entity.DashboardHostCount, error){repo.ListTopHostVulnerabilities, repo.ListTopHostPorts} {
		counts, err := query(context.Background())
		if err != nil || counts[0] != (entity.DashboardHostCount{IPAddress: "10.0.0.12", Count: 2}) {
			t.Fatalf("descending counts = %+v, error = %v", counts, err)
		}
	}
	for _, query := range []func(context.Context) ([]entity.DashboardFingerprintCount, error){repo.ListTopDomainFingerprints, repo.ListTopHostFingerprints} {
		counts, err := query(context.Background())
		if err != nil || counts[0].Count != 2 {
			t.Fatalf("descending fingerprints = %+v, error = %v", counts, err)
		}
	}
}

func TestDashboardRepositoryEmptyAndCancelled(t *testing.T) {
	t.Parallel()
	repo := NewDashboardRepository(openDashboardTestDB(t))
	for _, query := range []func(context.Context) (entity.DashboardAssetRiskCount, error){repo.FindHostRiskCounts, repo.FindDomainRiskCounts} {
		got, err := query(context.Background())
		if err != nil || !reflect.DeepEqual(got, entity.DashboardAssetRiskCount{}) {
			t.Fatalf("empty risk counts = %+v, error = %v", got, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repo.ListVulnerabilityCounts(ctx); err == nil {
		t.Fatal("cancelled query must return an error")
	}
}

func BenchmarkDashboardQueries(benchmark *testing.B) {
	db := openDashboardTestDB(benchmark)
	hosts := make([]entity.AssetHost, 1000)
	domains := make([]entity.AssetDomain, 1000)
	for index := range hosts {
		hosts[index].IPAddress = fmt.Sprintf("10.0.%d.%d", index/256, index%256)
		domains[index].Domain = fmt.Sprintf("app%d.example.com:443", index)
	}
	createDashboardRows(benchmark, db, &hosts)
	createDashboardRows(benchmark, db, &domains)
	vulnerabilities := make([]entity.Vulnerability, 100000)
	ports := make([]entity.AssetHostPort, 100000)
	fingerprints := make([]entity.AssetDomainServiceAsset, 10000)
	statuses := []string{"unreviewed", "confirmed", "ticketed", "fixed", "false_positive", "ignored"}
	severities := []string{"critical", "high", "medium", "low", "info", "unknown"}
	for index := range vulnerabilities {
		vulnerabilities[index] = entity.Vulnerability{AssetHost: &hosts[index%1000].IPAddress, AssetEndpoint: &domains[index%1000].Domain, Status: statuses[index%6], Severity: severities[(index/6)%6]}
		ports[index] = entity.AssetHostPort{IPAddress: hosts[index%1000].IPAddress, IsAlive: index%5 != 0, IsHighRiskPort: assetDomainTestPtr(index%3 == 0), ServiceName: dashboardString(fmt.Sprintf("service%d", index%30))}
	}
	for index := range fingerprints {
		fingerprints[index] = entity.AssetDomainServiceAsset{Domain: domains[index%1000].Domain, AppName: fmt.Sprintf("app%d", index%30), IsAlive: index%5 != 0}
	}
	createDashboardRows(benchmark, db, &vulnerabilities)
	createDashboardRows(benchmark, db, &ports)
	createDashboardRows(benchmark, db, &fingerprints)
	for _, statement := range []string{
		"CREATE UNIQUE INDEX dashboard_host_ip ON manscan_asset_host(ip_address)",
		"CREATE UNIQUE INDEX dashboard_domain ON manscan_asset_domain(domain)",
		"CREATE INDEX dashboard_vuln_host ON manscan_vulnerabilities(asset_host, asset_port)",
		"CREATE INDEX dashboard_port_alive ON manscan_asset_host_port(is_alive)",
		"CREATE INDEX dashboard_port_high_risk ON manscan_asset_host_port(is_high_risk_port)",
		"CREATE INDEX dashboard_domain_service_alive ON manscan_asset_domain_service_assets(is_alive)",
	} {
		if err := db.Exec(statement).Error; err != nil {
			benchmark.Fatal(err)
		}
	}
	repo := NewDashboardRepository(db)
	ctx := context.Background()
	queries := map[string][]func() error{
		"overview": {
			func() error { _, err := repo.ListVulnerabilityCounts(ctx); return err },
			func() error { _, err := repo.CountHighRiskOpenPorts(ctx); return err },
		},
		"asset_risks": {
			func() error { _, err := repo.FindHostRiskCounts(ctx); return err },
			func() error { _, err := repo.FindDomainRiskCounts(ctx); return err },
		},
		"host_rankings": {
			func() error { _, err := repo.ListTopHostVulnerabilities(ctx); return err },
			func() error { _, err := repo.ListTopHostPorts(ctx); return err },
		},
		"service_fingerprints": {
			func() error { _, err := repo.ListTopDomainFingerprints(ctx); return err },
			func() error { _, err := repo.ListTopHostFingerprints(ctx); return err },
		},
	}
	for name, operations := range queries {
		benchmark.Run(name, func(benchmark *testing.B) {
			benchmark.ReportAllocs()
			for iteration := 0; iteration < benchmark.N; iteration++ {
				for _, operation := range operations {
					if err := operation(); err != nil {
						benchmark.Fatal(err)
					}
				}
			}
		})
	}
}
