package entity

import "time"

type AssetDomainServiceAsset struct {
	ID           int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Domain       string    `gorm:"column:domain;not null"`
	AppName      string    `gorm:"column:app_name;not null"`
	AppVersion   string    `gorm:"column:app_version;not null"`
	LastFoundAt  time.Time `gorm:"column:last_found_at;not null"`
	FirstFoundAt time.Time `gorm:"column:first_found_at;not null"`
}

func (AssetDomainServiceAsset) TableName() string {
	return "manscan_asset_domain_service_assets"
}
