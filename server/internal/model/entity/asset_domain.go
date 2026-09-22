package entity

import "time"

type AssetDomain struct {
	ID                 int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Domain             string     `gorm:"column:domain"`
	Owner              *string    `gorm:"column:owner"`
	Title              *string    `gorm:"column:title"`
	CrawlerPathCount   int        `gorm:"column:crawler_path_count"`
	WhiteboxPathCount  int        `gorm:"column:whitebox_path_count"`
	FirstAliveAt       *time.Time `gorm:"column:first_alive_at"`
	LastAliveAt        *time.Time `gorm:"column:last_alive_at"`
	Region             *string    `gorm:"column:region"`
	VulnerabilityCount int        `gorm:"column:vulnerability_count"`
	CriticalCount      int        `gorm:"column:critical_count"`
	HighCount          int        `gorm:"column:high_count"`
	MediumCount        int        `gorm:"column:medium_count"`
	LowCount           int        `gorm:"column:low_count"`
	Components         *string    `gorm:"column:components"`
	ComponentCount     int        `gorm:"column:component_count"`
	RiskLevel          *string    `gorm:"column:risk_level"`
	HasForm            bool       `gorm:"column:has_form"`
	HasUpload          bool       `gorm:"column:has_upload"`
	HasAdmin           bool       `gorm:"column:has_admin"`
	HasUCLogin         bool       `gorm:"column:has_uc_login"`
	HasBaiduLogin      bool       `gorm:"column:has_baidu_login"`
	ScreenshotPath     *string    `gorm:"column:screenshot_path"`
	ManualNote         *string    `gorm:"column:manual_note"`
	HTTPStatusCode     *uint      `gorm:"column:http_status_code"`
	IsAlive            bool       `gorm:"column:is_alive"`
}

func (AssetDomain) TableName() string {
	return "manscan_asset_domain"
}
