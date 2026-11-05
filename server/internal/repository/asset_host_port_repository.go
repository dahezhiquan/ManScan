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
		items := make([]map[string]interface{}, 0, end-start)
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
			items = append(items, item)
		}
		if err := r.db.WithContext(ctx).
			Table("manscan_asset_host_port").
			Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "ip_address"},
					{Name: "port_protocol"},
					{Name: "port_number"},
					{Name: "service_name"},
				},
				DoUpdates: clause.AssignmentColumns([]string{
					"region",
					"last_alive_at",
					"app_name",
					"app_version",
					"is_alive",
				}),
			}).
			Create(&items).Error; err != nil {
			return err
		}
	}
	return nil
}

func uniqueAssetHostPortObservations(values []AssetHostPortObservation) []AssetHostPortObservation {
	result := make([]AssetHostPortObservation, 0, len(values))
	seen := make(map[string]struct{}, len(values))
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
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}
