package entity

import "time"

// AttackPathTask stores a durable classification request and its downloadable result.
type AttackPathTask struct {
	ID             string     `gorm:"column:id;type:char(32);primaryKey"`
	OwnerUserID    int64      `gorm:"column:owner_user_id;not null;index"`
	Status         string     `gorm:"column:status;type:varchar(16);not null;index"`
	OutputFileName string     `gorm:"column:output_file_name;type:varchar(96)"`
	Total          int        `gorm:"column:total;not null"`
	Processed      int        `gorm:"column:processed;not null;default:0"`
	Kept           int        `gorm:"column:kept;not null;default:0"`
	ErrorMessage   string     `gorm:"column:error_message;type:varchar(512)"`
	LeaseToken     string     `gorm:"column:lease_token;type:char(32)"`
	LeaseUntil     *time.Time `gorm:"column:lease_until;index"`
	CreatedAt      time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt      time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	FinishedAt     *time.Time `gorm:"column:finished_at"`
}

// TableName returns the persistent task table.
func (AttackPathTask) TableName() string { return "manscan_attack_path_tasks" }
