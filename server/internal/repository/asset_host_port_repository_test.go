package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestAssetHostPortRepositorySyncObservationsUpsertsAlivePorts(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.AssetHostPort{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX uk_ip_protocol_port ON manscan_asset_host_port(ip_address, port_protocol, port_number, service_name)").Error; err != nil {
		t.Fatalf("create unique index error = %v", err)
	}

	createdAt := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	laterAt := createdAt.Add(time.Hour)
	repo := NewAssetHostPortRepository(db)
	if err := repo.SyncObservations(context.Background(), []AssetHostPortObservation{{
		IPAddress:   "10.72.160.153",
		Region:      "生产内网",
		PortNumber:  8670,
		ServiceName: "redis",
		AppName:     "redis",
		IsAlive:     true,
	}}, createdAt); err != nil {
		t.Fatalf("SyncObservations() insert error = %v", err)
	}
	if err := repo.SyncObservations(context.Background(), []AssetHostPortObservation{{
		IPAddress:   "10.72.160.153",
		Region:      "生产内网",
		PortNumber:  8670,
		ServiceName: "redis",
		AppName:     "redis",
		AppVersion:  "7.2.1",
		IsAlive:     true,
	}}, laterAt); err != nil {
		t.Fatalf("SyncObservations() update error = %v", err)
	}

	var port entity.AssetHostPort
	if err := db.Where("ip_address = ? AND port_protocol = ? AND port_number = ?", "10.72.160.153", "", 8670).First(&port).Error; err != nil {
		t.Fatalf("First() error = %v", err)
	}
	if port.PortProtocol != "" {
		t.Fatalf("PortProtocol = %q, want empty default", port.PortProtocol)
	}
	if !port.PortCreatedAt.Equal(createdAt) {
		t.Fatalf("PortCreatedAt = %v, want first observed time %v", port.PortCreatedAt, createdAt)
	}
	if port.LastAliveAt == nil || !port.LastAliveAt.Equal(laterAt) {
		t.Fatalf("LastAliveAt = %v, want latest observed time %v", port.LastAliveAt, laterAt)
	}
	if port.ServiceName == nil || *port.ServiceName != "redis" {
		t.Fatalf("ServiceName = %v, want redis", port.ServiceName)
	}
	if port.AppVersion == nil || *port.AppVersion != "7.2.1" {
		t.Fatalf("AppVersion = %v, want 7.2.1", port.AppVersion)
	}
	if !port.IsAlive {
		t.Fatal("IsAlive = false, want true")
	}
	if port.IsHighRiskPort != nil {
		t.Fatalf("IsHighRiskPort = %v, want NULL when risk is unknown", *port.IsHighRiskPort)
	}
}

func TestAssetHostPortRepositorySyncObservationsKeepsServicesOnSamePort(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.AssetHostPort{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX uk_ip_protocol_port ON manscan_asset_host_port(ip_address, port_protocol, port_number, service_name)").Error; err != nil {
		t.Fatalf("create unique index error = %v", err)
	}

	first := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	later := first.Add(time.Hour)
	repo := NewAssetHostPortRepository(db)
	observations := []AssetHostPortObservation{
		{IPAddress: "10.72.160.153", PortProtocol: "tcp", PortNumber: 8080, ServiceName: "nginx", IsAlive: true},
		{IPAddress: "10.72.160.153", PortProtocol: "tcp", PortNumber: 8080, ServiceName: "tomcat", IsAlive: true},
	}
	if err := repo.SyncObservations(context.Background(), observations, first); err != nil {
		t.Fatalf("SyncObservations() insert error = %v", err)
	}
	if err := repo.SyncObservations(context.Background(), []AssetHostPortObservation{
		{IPAddress: "10.72.160.153", PortProtocol: "tcp", PortNumber: 8080, ServiceName: "nginx", AppVersion: "1.24", IsAlive: true},
	}, later); err != nil {
		t.Fatalf("SyncObservations() update error = %v", err)
	}

	var ports []entity.AssetHostPort
	if err := db.Order("service_name ASC").Find(&ports).Error; err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("port records = %d, want two services on one port", len(ports))
	}
	if ports[0].ServiceName == nil || *ports[0].ServiceName != "nginx" || ports[0].AppVersion == nil || *ports[0].AppVersion != "1.24" || !ports[0].PortCreatedAt.Equal(first) || ports[0].LastAliveAt == nil || !ports[0].LastAliveAt.Equal(later) {
		t.Fatalf("nginx port = %+v, want independently updated service", ports[0])
	}
	if ports[1].ServiceName == nil || *ports[1].ServiceName != "tomcat" || !ports[1].PortCreatedAt.Equal(first) || ports[1].LastAliveAt == nil || !ports[1].LastAliveAt.Equal(first) {
		t.Fatalf("tomcat port = %+v, want unchanged second service", ports[1])
	}
}

func TestAssetHostPortRepositorySyncObservationsKeepsKnownVersion(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&entity.AssetHostPort{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX uk_ip_protocol_port ON manscan_asset_host_port(ip_address, port_protocol, port_number, service_name)").Error; err != nil {
		t.Fatal(err)
	}

	repo := NewAssetHostPortRepository(db)
	first := time.Date(2026, 11, 5, 20, 23, 11, 0, time.UTC)
	base := AssetHostPortObservation{IPAddress: "10.107.71.95", PortProtocol: "tcp", PortNumber: 8022, ServiceName: "ssh", AppName: "ssh", IsAlive: true}
	withVersion := base
	withVersion.AppVersion = "OpenSSH 7.4"
	if err := repo.SyncObservations(context.Background(), []AssetHostPortObservation{base, withVersion}, first); err != nil {
		t.Fatal(err)
	}
	if err := repo.SyncObservations(context.Background(), []AssetHostPortObservation{base}, first.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	var port entity.AssetHostPort
	if err := db.Where("ip_address = ? AND port_protocol = ? AND port_number = ? AND service_name = ?", base.IPAddress, base.PortProtocol, base.PortNumber, base.ServiceName).First(&port).Error; err != nil {
		t.Fatal(err)
	}
	if port.AppVersion == nil || *port.AppVersion != "OpenSSH 7.4" {
		t.Fatalf("AppVersion = %v, want OpenSSH 7.4", port.AppVersion)
	}
	if port.LastAliveAt == nil || !port.LastAliveAt.Equal(first.Add(time.Second)) {
		t.Fatalf("LastAliveAt = %v, want latest observation", port.LastAliveAt)
	}
}

func TestAssetHostPortRepositoryMarkHTTPPortsInactiveUpdatesExistingHTTPOnly(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := db.AutoMigrate(&entity.AssetHostPort{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	httpName := "http"
	redisName := "redis"
	if err := db.Create(&[]entity.AssetHostPort{
		{
			IPAddress:     "10.72.160.153",
			LastAliveAt:   &now,
			PortCreatedAt: now,
			PortNumber:    80,
			ServiceName:   &httpName,
			AppName:       &httpName,
			IsAlive:       true,
		},
		{
			IPAddress:     "10.72.160.153",
			LastAliveAt:   &now,
			PortCreatedAt: now,
			PortNumber:    6379,
			ServiceName:   &redisName,
			AppName:       &redisName,
			IsAlive:       true,
		},
	}).Error; err != nil {
		t.Fatalf("Create host ports error = %v", err)
	}

	repo := NewAssetHostPortRepository(db)
	if err := repo.MarkHTTPPortsInactive(context.Background(), []AssetHostPortObservation{
		{IPAddress: "10.72.160.153", PortNumber: 80},
		{IPAddress: "10.72.160.153", PortNumber: 6379},
		{IPAddress: "10.72.160.200", PortNumber: 80},
	}); err != nil {
		t.Fatalf("MarkHTTPPortsInactive() error = %v", err)
	}

	var httpPort entity.AssetHostPort
	if err := db.Where("ip_address = ? AND port_number = ?", "10.72.160.153", 80).First(&httpPort).Error; err != nil {
		t.Fatalf("First http port error = %v", err)
	}
	if httpPort.IsAlive {
		t.Fatal("http port IsAlive = true, want false")
	}

	var redisPort entity.AssetHostPort
	if err := db.Where("ip_address = ? AND port_number = ?", "10.72.160.153", 6379).First(&redisPort).Error; err != nil {
		t.Fatalf("First redis port error = %v", err)
	}
	if !redisPort.IsAlive {
		t.Fatal("redis port IsAlive = false, want true")
	}

	var count int64
	if err := db.Model(&entity.AssetHostPort{}).Where("ip_address = ?", "10.72.160.200").Count(&count).Error; err != nil {
		t.Fatalf("Count non-existing port error = %v", err)
	}
	if count != 0 {
		t.Fatalf("non-existing port count = %d, want 0", count)
	}
}

func TestAssetHostPortRepositoryMarkServicesInactivePreservesObservationTimes(t *testing.T) {
	t.Parallel()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&entity.AssetHostPort{}); err != nil {
		t.Fatal(err)
	}
	first := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	last := first.Add(time.Hour)
	services := []string{"nginx", "tomcat", "ssh"}
	ports := make([]entity.AssetHostPort, 0, len(services))
	for _, name := range services {
		name := name
		ports = append(ports, entity.AssetHostPort{
			IPAddress: "10.0.0.1", PortProtocol: "tcp", PortNumber: 8080,
			ServiceName: &name, PortCreatedAt: first, LastAliveAt: &last, IsAlive: true,
		})
	}
	if err := db.Create(&ports).Error; err != nil {
		t.Fatal(err)
	}
	repo := NewAssetHostPortRepository(db)
	if err := repo.MarkServicesInactive(context.Background(), "10.0.0.1", 8080, []AssetHostPortObservation{
		{IPAddress: "10.0.0.1", PortProtocol: "tcp", PortNumber: 8080, ServiceName: "nginx"},
		{IPAddress: "10.0.0.1", PortProtocol: "tcp", PortNumber: 8080, ServiceName: "tomcat"},
	}); err != nil {
		t.Fatal(err)
	}
	var got []entity.AssetHostPort
	if err := db.Order("service_name ASC").Find(&got).Error; err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("ports = %d, want 3", len(got))
	}
	for _, port := range got {
		if port.PortCreatedAt != first || port.LastAliveAt == nil || !port.LastAliveAt.Equal(last) {
			t.Fatalf("service %v observation times changed: %+v", port.ServiceName, port)
		}
		wantAlive := *port.ServiceName != "ssh"
		if port.IsAlive != wantAlive {
			t.Fatalf("service %s alive = %v, want %v", *port.ServiceName, port.IsAlive, wantAlive)
		}
	}
}
