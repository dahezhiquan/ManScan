package dto

import "time"

type ListAssetHostsQuery struct {
	Page             int
	PageSize         int
	Keyword          string
	Owner            string
	OSType           string
	Region           string
	AssetAddress     string
	RiskLevels       []string
	HasVulnerability *bool
	HasPort          *bool
	IsAlive          *bool
}

type AssetHostListItem struct {
	ID                 int64      `json:"id"`
	IPAddress          string     `json:"ip_address"`
	AssetAddress       string     `json:"asset_address"`
	Region             string     `json:"region"`
	Owner              string     `json:"owner"`
	OSType             string     `json:"os_type"`
	OSVersion          string     `json:"os_version"`
	ScanCreatedAt      time.Time  `json:"scan_created_at"`
	LastAliveAt        *time.Time `json:"last_alive_at"`
	ManualNote         string     `json:"manual_note"`
	IsAlive            bool       `json:"is_alive"`
	RelatedDomains     string     `json:"related_domains"`
	RiskLevel          string     `json:"risk_level"`
	VulnerabilityCount int        `json:"vulnerability_count"`
	CriticalCount      int        `json:"critical_count"`
	HighCount          int        `json:"high_count"`
	MediumCount        int        `json:"medium_count"`
	LowCount           int        `json:"low_count"`
	PortCount          int        `json:"port_count"`
}

type AssetHostDetail struct {
	IPAddress          string                    `json:"ip_address"`
	Region             string                    `json:"region"`
	Owner              string                    `json:"owner"`
	OSType             string                    `json:"os_type"`
	OSVersion          string                    `json:"os_version"`
	ScanCreatedAt      time.Time                 `json:"scan_created_at"`
	LastAliveAt        *time.Time                `json:"last_alive_at"`
	ManualNote         string                    `json:"manual_note"`
	IsAlive            bool                      `json:"is_alive"`
	RelatedDomains     string                    `json:"related_domains"`
	RiskLevel          string                    `json:"risk_level"`
	VulnerabilityCount int                       `json:"vulnerability_count"`
	Ports              []AssetHostPortDetailItem `json:"ports"`
}

type AssetHostPortDetailItem struct {
	PortProtocol   string     `json:"port_protocol"`
	PortNumber     uint       `json:"port_number"`
	ServiceName    string     `json:"service_name"`
	AppName        string     `json:"app_name"`
	AppVersion     string     `json:"app_version"`
	IsAlive        bool       `json:"is_alive"`
	IsHighRiskPort bool       `json:"is_high_risk_port"`
	LastAliveAt    *time.Time `json:"last_alive_at"`
	PortCreatedAt  time.Time  `json:"port_created_at"`
}
