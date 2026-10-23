package entity

import "time"

// ScheduledJob 保存通用后台定时任务定义。
type ScheduledJob struct {
	ID                int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Name              string     `gorm:"column:name;type:varchar(128);not null"`
	Description       string     `gorm:"column:description;type:varchar(512);not null;default:''"`
	JobType           string     `gorm:"column:job_type;type:varchar(64);not null"`
	CronExpr          string     `gorm:"column:cron_expr;type:varchar(64);not null"`
	Timezone          string     `gorm:"column:timezone;type:varchar(64);not null;default:'Asia/Shanghai'"`
	Enabled           bool       `gorm:"column:enabled;not null;default:true"`
	APIKeyID          *int64     `gorm:"column:api_key_id"`
	ConfigJSON        string     `gorm:"column:config_json;type:json;not null"`
	ConcurrencyPolicy string     `gorm:"column:concurrency_policy;type:varchar(16);not null;default:'forbid'"`
	TimeoutSeconds    int        `gorm:"column:timeout_seconds;not null;default:300"`
	NextRunAt         *time.Time `gorm:"column:next_run_at"`
	LastRunAt         *time.Time `gorm:"column:last_run_at"`
	LastStatus        string     `gorm:"column:last_status;type:varchar(32)"`
	LastError         string     `gorm:"column:last_error;type:varchar(1024)"`
	CreatedAt         time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt         time.Time  `gorm:"column:updated_at;autoUpdateTime"`
}

// TableName 返回定时任务表名。
func (ScheduledJob) TableName() string { return "manscan_scheduled_jobs" }
