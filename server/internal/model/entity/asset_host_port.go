package entity

import "time"

type AssetHostPort struct {
	ID               int64      `gorm:"column:id;primaryKey;autoIncrement"`
	IPAddress        string     `gorm:"column:ip_address"`
	Region           *string    `gorm:"column:region"`
	LastAliveAt      *time.Time `gorm:"column:last_alive_at"`
	PortCreatedAt    time.Time  `gorm:"column:port_created_at"`
	PortProtocol     string     `gorm:"column:port_protocol"`
	PortNumber       uint       `gorm:"column:port_number"`
	ServiceName      *string    `gorm:"column:service_name"`
	AppName          *string    `gorm:"column:app_name"`
	AppVersion       *string    `gorm:"column:app_version"`
	IsAlive          bool       `gorm:"column:is_alive"`
	HasVulnerability bool       `gorm:"column:has_vulnerability"`
	IsHighRiskPort   bool       `gorm:"column:is_high_risk_port"`
}

func (AssetHostPort) TableName() string {
	return "manscan_asset_host_port"
}
