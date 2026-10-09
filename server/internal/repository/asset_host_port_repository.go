package repository

import (
	"context"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AssetHostPortRepository interface {
	SyncObservations(ctx context.Context, observations []AssetHostPortObservation, observedAt time.Time) error
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
				"service_name":    nil,
				"app_name":        nil,
				"app_version":     nil,
				"is_alive":        observation.IsAlive,
			}
			if observation.Region != "" {
				item["region"] = observation.Region
			}
			if observation.ServiceName != "" {
				item["service_name"] = observation.ServiceName
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
				},
				DoUpdates: clause.AssignmentColumns([]string{
					"region",
					"last_alive_at",
					"service_name",
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
		value.PortProtocol = strings.TrimSpace(value.PortProtocol)
		value.ServiceName = strings.TrimSpace(value.ServiceName)
		value.AppName = strings.TrimSpace(value.AppName)
		value.AppVersion = strings.TrimSpace(value.AppVersion)
		if value.IPAddress == "" || value.PortNumber == 0 {
			continue
		}
		key := value.IPAddress + "\x00" + value.PortProtocol + "\x00" + strconv.FormatUint(uint64(value.PortNumber), 10)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}
