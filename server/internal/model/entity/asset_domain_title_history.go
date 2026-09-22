package entity

import "time"

type AssetDomainTitleHistory struct {
	ID                  int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Domain              string    `gorm:"column:domain;not null"`
	HistoryTitle        string    `gorm:"column:history_title;not null"`
	FirstTitleCreatedAt time.Time `gorm:"column:first_title_created_at;not null"`
	LatestTitleAliveAt  time.Time `gorm:"column:latest_title_alive_at;type:date;not null"`
	IsAlive             bool      `gorm:"column:is_alive;not null;default:false"`
}

func (AssetDomainTitleHistory) TableName() string {
	return "manscan_asset_domain_title_history"
}
