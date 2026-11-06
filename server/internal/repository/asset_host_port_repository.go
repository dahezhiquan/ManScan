package repository

import (
	"context"
	"strconv"
	"strings"
	"time"

	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AssetHostPortRepository interface {
	SyncObservations(ctx context.Context, observations []AssetHostPortObservation, observedAt time.Time) error
	MarkHTTPPortsInactive(ctx context.Context, observations []AssetHostPortObservation) error
	MarkServicesInactive(ctx context.Context, ipAddress string, portNumber uint, observed []AssetHostPortObservation) error
}

type assetHostPortRepository struct {
	db *gorm.DB
}

type AssetHostPortObservation struct {
	IPAddress    string
	Region       string
	PortProtocol string
	PortNumber   uint
	ServiceName  string
	AppName      string
	AppVersion   string
	IsAlive      bool
}

func NewAssetHostPortRepository(db *gorm.DB) AssetHostPortRepository {
	return &assetHostPortRepository{db: db}
}

func (r *assetHostPortRepository) MarkHTTPPortsInactive(ctx context.Context, observations []AssetHostPortObservation) error {
	observations = uniqueAssetHostPortObservations(observations)
	if len(observations) == 0 {
		return nil
	}

	for _, observation := range observations {
		if err := r.db.WithContext(ctx).
			Model(&entity.AssetHostPort{}).
			Where("ip_address = ? AND port_number = ?", observation.IPAddress, observation.PortNumber).
			Where("(LOWER(COALESCE(service_name, '')) = ? OR LOWER(COALESCE(app_name, '')) = ?)", "http", "http").
			Update("is_alive", false).Error; err != nil {
			return err
		}
	}
	return nil
}

// MarkServicesInactive marks unobserved services on one IP port inactive without changing observation times.
func (r *assetHostPortRepository) MarkServicesInactive(ctx context.Context, ipAddress string, portNumber uint, observed []AssetHostPortObservation) error {
	if ipAddress == "" || portNumber == 0 {
		return nil
	}
	query := r.db.WithContext(ctx).Model(&entity.AssetHostPort{}).
		Where("ip_address = ? AND port_number = ? AND is_alive = ?", ipAddress, portNumber, true)
	for _, item := range uniqueAssetHostPortObservations(observed) {
		if item.IPAddress == ipAddress && item.PortNumber == portNumber {
			query = query.Where("NOT (port_protocol = ? AND service_name = ?)", item.PortProtocol, item.ServiceName)
		}
	}
	return query.Update("is_alive", false).Error
}

func (r *assetHostPortRepository) SyncObservations(ctx context.Context, observations []AssetHostPortObservation, observedAt time.Time) error {
	observations = uniqueAssetHostPortObservations(observations)
	if len(observations) == 0 {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}

	const batchSize = 500
	for start := 0; start < len(observations); start += batchSize {
		end := start + batchSize
		if end > len(observations) {
			end = len(observations)
		}
		batch := observations[start:end]
		if err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var err error
			batch, err = resolveUnknownAssetHostPortProtocols(tx, batch)
			if err != nil {
				return err
			}
			if err := syncAssetHostPortBatch(tx, batch, observedAt); err != nil {
				return err
			}
			return mergeUnknownAssetHostPortProtocols(tx, batch)
		}); err != nil {
			return err
		}
	}
	return nil
}

func resolveUnknownAssetHostPortProtocols(db *gorm.DB, batch []AssetHostPortObservation) ([]AssetHostPortObservation, error) {
	type portKey struct {
		ipAddress   string
		portNumber  uint
		serviceName string
	}
	known := make(map[portKey]string, len(batch))
	unknownKeys := make(map[portKey]struct{})
	for _, observation := range batch {
		key := portKey{observation.IPAddress, observation.PortNumber, observation.ServiceName}
		if observation.PortProtocol == "" {
			unknownKeys[key] = struct{}{}
			continue
		}
		if previous := known[key]; previous != "" && previous != observation.PortProtocol {
			known[key] = "ambiguous"
		} else if previous != "ambiguous" {
			known[key] = observation.PortProtocol
		}
	}
	keys := make([][]interface{}, 0, len(unknownKeys))
	for key := range unknownKeys {
		keys = append(keys, []interface{}{key.ipAddress, key.portNumber, key.serviceName})
	}
	if len(keys) == 0 {
		return batch, nil
	}
	var existing []entity.AssetHostPort
	if err := db.Where("port_protocol <> ? AND (ip_address, port_number, service_name) IN ?", "", keys).Find(&existing).Error; err != nil {
		return nil, err
	}
	for _, port := range existing {
		serviceName := ""
		if port.ServiceName != nil {
			serviceName = *port.ServiceName
		}
		key := portKey{port.IPAddress, port.PortNumber, serviceName}
		if previous := known[key]; previous != "" && previous != port.PortProtocol {
			known[key] = "ambiguous"
		} else if previous != "ambiguous" {
			known[key] = port.PortProtocol
		}
	}
	for index := range batch {
		if batch[index].PortProtocol != "" {
			continue
		}
		key := portKey{batch[index].IPAddress, batch[index].PortNumber, batch[index].ServiceName}
		if protocol := known[key]; protocol == "tcp" || protocol == "udp" {
			batch[index].PortProtocol = protocol
		}
	}
	return uniqueAssetHostPortObservations(batch), nil
}

func syncAssetHostPortBatch(db *gorm.DB, batch []AssetHostPortObservation, observedAt time.Time) error {
	itemsByVersion := [2][]map[string]interface{}{}
	for _, observation := range batch {
		item := map[string]interface{}{
			"ip_address":      observation.IPAddress,
			"region":          nil,
			"last_alive_at":   observedAt,
			"port_created_at": observedAt,
			"port_protocol":   observation.PortProtocol,
			"port_number":     observation.PortNumber,
			"service_name":    observation.ServiceName,
			"app_name":        nil,
			"app_version":     nil,
			"is_alive":        observation.IsAlive,
		}
		if observation.Region != "" {
			item["region"] = observation.Region
		}
		if observation.AppName != "" {
			item["app_name"] = observation.AppName
		}
		if observation.AppVersion != "" {
			item["app_version"] = observation.AppVersion
		}
		versionIndex := 0
		if observation.AppVersion != "" {
			versionIndex = 1
		}
		itemsByVersion[versionIndex] = append(itemsByVersion[versionIndex], item)
	}
	for versionIndex, items := range itemsByVersion {
		if len(items) == 0 {
			continue
		}
		updateColumns := []string{"region", "last_alive_at", "app_name", "is_alive"}
		if versionIndex == 1 {
			updateColumns = append(updateColumns, "app_version")
		}
		if err := db.
			Table("manscan_asset_host_port").
			Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "ip_address"},
					{Name: "port_protocol"},
					{Name: "port_number"},
					{Name: "service_name"},
				},
				DoUpdates: clause.AssignmentColumns(updateColumns),
			}).
			Create(&items).Error; err != nil {
			return err
		}
	}
	return nil
}

func mergeUnknownAssetHostPortProtocols(db *gorm.DB, batch []AssetHostPortObservation) error {
	type knownPort struct {
		ipAddress   string
		portNumber  uint
		serviceName string
		protocol    string
	}
	knownByKey := make(map[string]knownPort, len(batch))
	for _, observation := range batch {
		if observation.PortProtocol != "tcp" && observation.PortProtocol != "udp" {
			continue
		}
		key := observation.IPAddress + "\x00" + strconv.FormatUint(uint64(observation.PortNumber), 10) + "\x00" + observation.ServiceName
		if existing, ok := knownByKey[key]; ok && existing.protocol != observation.PortProtocol {
			existing.protocol = "ambiguous"
			knownByKey[key] = existing
			continue
		}
		knownByKey[key] = knownPort{observation.IPAddress, observation.PortNumber, observation.ServiceName, observation.PortProtocol}
	}
	keys := make([][]interface{}, 0, len(knownByKey))
	for _, port := range knownByKey {
		if port.protocol == "tcp" || port.protocol == "udp" {
			keys = append(keys, []interface{}{port.ipAddress, port.portNumber, port.serviceName})
		}
	}
	if len(keys) == 0 {
		return nil
	}

	var unknownPorts []entity.AssetHostPort
	if err := db.Where("port_protocol = ? AND (ip_address, port_number, service_name) IN ?", "", keys).Find(&unknownPorts).Error; err != nil {
		return err
	}
	if len(unknownPorts) == 0 {
		return nil
	}
	var existingKnownPorts []entity.AssetHostPort
	if err := db.Where("port_protocol <> ? AND (ip_address, port_number, service_name) IN ?", "", keys).Find(&existingKnownPorts).Error; err != nil {
		return err
	}
	for _, existing := range existingKnownPorts {
		serviceName := ""
		if existing.ServiceName != nil {
			serviceName = *existing.ServiceName
		}
		key := existing.IPAddress + "\x00" + strconv.FormatUint(uint64(existing.PortNumber), 10) + "\x00" + serviceName
		if port := knownByKey[key]; port.protocol != existing.PortProtocol {
			port.protocol = "ambiguous"
			knownByKey[key] = port
		}
	}
	for _, unknown := range unknownPorts {
		serviceName := ""
		if unknown.ServiceName != nil {
			serviceName = *unknown.ServiceName
		}
		key := unknown.IPAddress + "\x00" + strconv.FormatUint(uint64(unknown.PortNumber), 10) + "\x00" + serviceName
		port := knownByKey[key]
		if port.protocol != "tcp" && port.protocol != "udp" {
			continue
		}
		var known entity.AssetHostPort
		if err := db.Where("ip_address = ? AND port_protocol = ? AND port_number = ? AND service_name = ?", port.ipAddress, port.protocol, port.portNumber, port.serviceName).First(&known).Error; err != nil {
			return err
		}
		updates := map[string]interface{}{}
		if unknown.PortCreatedAt.Before(known.PortCreatedAt) {
			updates["port_created_at"] = unknown.PortCreatedAt
		}
		if unknown.LastAliveAt != nil && (known.LastAliveAt == nil || unknown.LastAliveAt.After(*known.LastAliveAt)) {
			updates["last_alive_at"] = unknown.LastAliveAt
		}
		if known.Region == nil && unknown.Region != nil {
			updates["region"] = unknown.Region
		}
		if known.AppName == nil && unknown.AppName != nil {
			updates["app_name"] = unknown.AppName
		}
		if known.AppVersion == nil && unknown.AppVersion != nil {
			updates["app_version"] = unknown.AppVersion
		}
		if known.IsHighRiskPort == nil && unknown.IsHighRiskPort != nil {
			updates["is_high_risk_port"] = unknown.IsHighRiskPort
		}
		if len(updates) > 0 {
			if err := db.Model(&known).Updates(updates).Error; err != nil {
				return err
			}
		}
		if err := db.Delete(&unknown).Error; err != nil {
			return err
		}
	}
	return nil
}

func uniqueAssetHostPortObservations(values []AssetHostPortObservation) []AssetHostPortObservation {
	result := make([]AssetHostPortObservation, 0, len(values))
	seen := make(map[string]int, len(values))
	for _, value := range values {
		value.IPAddress = strings.TrimSpace(value.IPAddress)
		value.Region = strings.TrimSpace(value.Region)
		value.PortProtocol = strings.ToLower(strings.TrimSpace(value.PortProtocol))
		value.ServiceName = strings.TrimSpace(value.ServiceName)
		value.AppName = strings.TrimSpace(value.AppName)
		value.AppVersion = strings.TrimSpace(value.AppVersion)
		if value.IPAddress == "" || value.PortNumber == 0 {
			continue
		}
		key := value.IPAddress + "\x00" + value.PortProtocol + "\x00" + strconv.FormatUint(uint64(value.PortNumber), 10) + "\x00" + value.ServiceName
		if index, ok := seen[key]; ok {
			if result[index].AppVersion == "" && value.AppVersion != "" {
				result[index].AppVersion = value.AppVersion
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, value)
	}
	return result
}
