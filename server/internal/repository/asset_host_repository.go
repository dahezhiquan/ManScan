package repository

import (
	"context"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AssetHostRepository interface {
	SyncObservations(ctx context.Context, observations []AssetHostObservation, observedAt time.Time) error
}

type assetHostRepository struct {
	db *gorm.DB
}

type AssetHostObservation struct {
	IPAddress string
	Region    string
	IsAlive   bool
}

func NewAssetHostRepository(db *gorm.DB) AssetHostRepository {
	return &assetHostRepository{db: db}
}

func (r *assetHostRepository) SyncObservations(ctx context.Context, observations []AssetHostObservation, observedAt time.Time) error {
	observations = uniqueAssetHostObservations(observations)
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
				"scan_created_at": observedAt,
				"last_alive_at":   observedAt,
				"is_alive":        observation.IsAlive,
				"region":          nil,
			}
			if observation.Region != "" {
				item["region"] = observation.Region
			}
			items = append(items, item)
		}
		if err := r.db.WithContext(ctx).
			Table("manscan_asset_host").
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "ip_address"}},
				DoUpdates: clause.AssignmentColumns([]string{"last_alive_at", "is_alive", "region"}),
			}).
			Create(&items).Error; err != nil {
			return err
		}
	}
	return nil
}

func uniqueAssetHostObservations(values []AssetHostObservation) []AssetHostObservation {
	result := make([]AssetHostObservation, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.IPAddress = strings.TrimSpace(value.IPAddress)
		value.Region = strings.TrimSpace(value.Region)
		if value.IPAddress == "" {
			continue
		}
		if _, ok := seen[value.IPAddress]; ok {
			continue
		}
		seen[value.IPAddress] = struct{}{}
		result = append(result, value)
	}
	return result
}
