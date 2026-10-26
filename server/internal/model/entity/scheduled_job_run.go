package entity

import "time"

// ScheduledJobRun 保存一次定时任务执行及其进度。
type ScheduledJobRun struct {
	ID                int64      `gorm:"column:id;primaryKey;autoIncrement"`
	JobID             int64      `gorm:"column:job_id;not null;index"`
	TriggerType       string     `gorm:"column:trigger_type;type:varchar(16);not null"`
	FireKey           string     `gorm:"column:fire_key;type:varchar(128);not null"`
	Status            string     `gorm:"column:status;type:varchar(32);not null"`
	ProgressCurrent   int64      `gorm:"column:progress_current;not null;default:0"`
	ProgressTotal     int64      `gorm:"column:progress_total;not null;default:0"`
	ProgressPhase     string     `gorm:"column:progress_phase;type:varchar(64)"`
	ProgressMessage   string     `gorm:"column:progress_message;type:varchar(512)"`
	ProgressUpdatedAt *time.Time `gorm:"column:progress_updated_at"`
	StartedAt         *time.Time `gorm:"column:started_at"`
	FinishedAt        *time.Time `gorm:"column:finished_at"`
	RelatedType       string     `gorm:"column:related_type;type:varchar(32)"`
	RelatedID         *int64     `gorm:"column:related_id"`
	OutputPath        string     `gorm:"column:output_path;type:varchar(1024)"`
	ResultRef         string     `gorm:"column:result_ref;type:varchar(1024)"`
	ResultSummary     *string    `gorm:"column:result_summary;type:json"`
	ErrorMessage      string     `gorm:"column:error_message;type:varchar(2048)"`
	CreatedAt         time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt         time.Time  `gorm:"column:updated_at;autoUpdateTime"`
}

// TableName 返回定时任务执行记录表名。
func (ScheduledJobRun) TableName() string { return "manscan_scheduled_job_runs" }
