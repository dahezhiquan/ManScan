package dto

import "time"

type ListAssetDomainsQuery struct {
	Page         int
	PageSize     int
	Keyword      string
	Owner        string
	Region       string
	AssetAddress string
	IsAlive      *bool
}

type AssetDomainListItem struct {
	ID                 int64      `json:"id"`
	Domain             string     `json:"domain"`
	AssetAddress       string     `json:"asset_address"`
	Owner              string     `json:"owner"`
	Title              string     `json:"title"`
	FirstAliveAt       *time.Time `json:"first_alive_at"`
	LastAliveAt        *time.Time `json:"last_alive_at"`
	Region             string     `json:"region"`
	HasForm            bool       `json:"has_form"`
	HasUpload          bool       `json:"has_upload"`
	HasAdmin           bool       `json:"has_admin"`
	HasUCLogin         bool       `json:"has_uc_login"`
	HasBaiduLogin      bool       `json:"has_baidu_login"`
	ScreenshotPath     string     `json:"screenshot_path"`
	ManualNote         string     `json:"manual_note"`
	HTTPStatusCode     *uint      `json:"http_status_code"`
	Request            string     `json:"request"`
	Response           string     `json:"response"`
	IsAlive            bool       `json:"is_alive"`
	VulnerabilityCount int        `json:"vulnerability_count"`
	CriticalCount      int        `json:"critical_count"`
	HighCount          int        `json:"high_count"`
	MediumCount        int        `json:"medium_count"`
	LowCount           int        `json:"low_count"`
	ComponentCount     int        `json:"component_count"`
}
