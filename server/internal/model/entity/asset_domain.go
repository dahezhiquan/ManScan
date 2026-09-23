package entity

import "time"

type AssetDomain struct {
	ID             int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Domain         string     `gorm:"column:domain"`
	Owner          *string    `gorm:"column:owner"`
	Title          *string    `gorm:"column:title"`
	FirstAliveAt   *time.Time `gorm:"column:first_alive_at"`
	LastAliveAt    *time.Time `gorm:"column:last_alive_at"`
	Region         *string    `gorm:"column:region"`
	HasForm        bool       `gorm:"column:has_form"`
	HasUpload      bool       `gorm:"column:has_upload"`
	HasAdmin       bool       `gorm:"column:has_admin"`
	HasUCLogin     bool       `gorm:"column:has_uc_login"`
	HasBaiduLogin  bool       `gorm:"column:has_baidu_login"`
	ScreenshotPath *string    `gorm:"column:screenshot_path"`
	ManualNote     *string    `gorm:"column:manual_note"`
	HTTPStatusCode *uint      `gorm:"column:http_status_code"`
	Request        *string    `gorm:"column:request"`
	Response       *string    `gorm:"column:response"`
	IsAlive        bool       `gorm:"column:is_alive"`
}

func (AssetDomain) TableName() string {
	return "manscan_asset_domain"
}
