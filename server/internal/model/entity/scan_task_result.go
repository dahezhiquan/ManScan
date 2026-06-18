package entity

import "time"

type ScanTaskResult struct {
	ID            int64      `gorm:"column:id;primaryKey;autoIncrement"`
	TaskID        int64      `gorm:"column:task_id"`
	TaskName      string     `gorm:"column:task_name"`
	CriticalCount int        `gorm:"column:critical_count"`
	HighCount     int        `gorm:"column:high_count"`
	MediumCount   int        `gorm:"column:medium_count"`
	LowCount      int        `gorm:"column:low_count"`
	InfoCount     int        `gorm:"column:info_count"`
	PluginCount   int        `gorm:"column:plugin_count"`
	TargetCount   int        `gorm:"column:target_count"`
	FinishedAt    *time.Time `gorm:"column:finished_at"`
}

func (ScanTaskResult) TableName() string {
	return "manscan_task_results"
}
