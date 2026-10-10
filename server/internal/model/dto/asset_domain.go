package dto

import "time"

type ListAssetDomainsQuery struct {
	Page             int
	PageSize         int
	Keyword          string
	Owner            string
	Title            string
	Region           string
	AssetAddress     string
	RiskLevels       []string
	HasVulnerability *bool
	HasComponent     *bool
	IsAlive          *bool
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
	RiskLevel          string     `json:"risk_level"`
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

type AssetDomainDetail struct {
	Domain         string                        `json:"domain"`
	Owner          string                        `json:"owner"`
	Title          string                        `json:"title"`
	FirstAliveAt   *time.Time                    `json:"first_alive_at"`
	LastAliveAt    *time.Time                    `json:"last_alive_at"`
	Region         string                        `json:"region"`
	HasForm        bool                          `json:"has_form"`
	HasUpload      bool                          `json:"has_upload"`
	HasAdmin       bool                          `json:"has_admin"`
	HasUCLogin     bool                          `json:"has_uc_login"`
	HasBaiduLogin  bool                          `json:"has_baidu_login"`
	ScreenshotPath string                        `json:"screenshot_path"`
	ManualNote     string                        `json:"manual_note"`
	HTTPStatusCode *uint                         `json:"http_status_code"`
	Request        string                        `json:"request"`
	Response       string                        `json:"response"`
	IsAlive        bool                          `json:"is_alive"`
	ServiceAssets  []AssetDomainServiceAssetItem `json:"service_assets"`
	TitleHistories []AssetDomainTitleHistoryItem `json:"title_histories"`
}

type AssetDomainServiceAssetItem struct {
	AppName      string    `json:"app_name"`
	AppVersion   string    `json:"app_version"`
	LastFoundAt  time.Time `json:"last_found_at"`
	FirstFoundAt time.Time `json:"first_found_at"`
	IsAlive      bool      `json:"is_alive"`
}

type AssetDomainTitleHistoryItem struct {
	HistoryTitle        string    `json:"history_title"`
	IsAlive             bool      `json:"is_alive"`
	FirstTitleCreatedAt time.Time `json:"first_title_created_at"`
	LatestTitleAliveAt  time.Time `json:"latest_title_alive_at"`
}
