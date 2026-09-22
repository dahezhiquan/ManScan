package entity

import "time"

type AssetHost struct {
	ID                 int64      `gorm:"column:id;primaryKey;autoIncrement"`
	IPAddress          string     `gorm:"column:ip_address"`
	Region             *string    `gorm:"column:region"`
	Owner              *string    `gorm:"column:owner"`
	OSType             *string    `gorm:"column:os_type"`
	OSVersion          *string    `gorm:"column:os_version"`
	ScanCreatedAt      time.Time  `gorm:"column:scan_created_at"`
	LastAliveAt        *time.Time `gorm:"column:last_alive_at"`
	PortCount          int        `gorm:"column:port_count"`
	HasHighRiskService bool       `gorm:"column:has_high_risk_service"`
	ManualNote         *string    `gorm:"column:manual_note"`
	RiskLevel          *string    `gorm:"column:risk_level"`
	VulnerabilityCount int        `gorm:"column:vulnerability_count"`
	IsAlive            bool       `gorm:"column:is_alive"`
	RelatedDomains     *string    `gorm:"column:related_domains"`
}

func (AssetHost) TableName() string {
	return "manscan_asset_host"
}
