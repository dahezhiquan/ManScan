package dto

import "time"

type CreateScheduledJobRequest struct {
	Name              string `json:"name" binding:"required,max=128"`
	Description       string `json:"description" binding:"max=512"`
	JobType           string `json:"job_type" binding:"required,max=64"`
	CronExpr          string `json:"cron_expr" binding:"required,max=64"`
	Timezone          string `json:"timezone" binding:"max=64"`
	Enabled           *bool  `json:"enabled"`
	APIKeyID          *int64 `json:"api_key_id"`
	ConfigJSON        string `json:"config_json" binding:"required"`
	ConcurrencyPolicy string `json:"concurrency_policy" binding:"max=16"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
}

type UpdateScheduledJobRequest struct {
	Name              string `json:"name" binding:"required,max=128"`
	Description       string `json:"description" binding:"max=512"`
	JobType           string `json:"job_type" binding:"required,max=64"`
	CronExpr          string `json:"cron_expr" binding:"required,max=64"`
	Timezone          string `json:"timezone" binding:"max=64"`
	Enabled           bool   `json:"enabled"`
	APIKeyID          *int64 `json:"api_key_id"`
	ConfigJSON        string `json:"config_json" binding:"required"`
	ConcurrencyPolicy string `json:"concurrency_policy" binding:"max=16"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
}

type ListScheduledJobsQuery struct {
	Page     int
	PageSize int
	Keyword  string
}

type ListScheduledJobRunsQuery struct {
	Page     int
	PageSize int
}

type ScheduledJobListItem struct {
	ID                int64      `json:"id"`
	Name              string     `json:"name"`
	Description       string     `json:"description"`
	JobType           string     `json:"job_type"`
	CronExpr          string     `json:"cron_expr"`
	Timezone          string     `json:"timezone"`
	Enabled           bool       `json:"enabled"`
	APIKeyID          *int64     `json:"api_key_id,omitempty"`
	ConfigJSON        string     `json:"config_json"`
	ConcurrencyPolicy string     `json:"concurrency_policy"`
	TimeoutSeconds    int        `json:"timeout_seconds"`
	NextRunAt         *time.Time `json:"next_run_at,omitempty"`
	LastRunAt         *time.Time `json:"last_run_at,omitempty"`
	LastStatus        string     `json:"last_status,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type ScheduledJobRunItem struct {
	ID                int64      `json:"id"`
	JobID             int64      `json:"job_id"`
	TriggerType       string     `json:"trigger_type"`
	Status            string     `json:"status"`
	ProgressCurrent   int64      `json:"progress_current"`
	ProgressTotal     int64      `json:"progress_total"`
	ProgressPercent   *float64   `json:"progress_percent,omitempty"`
	ProgressPhase     string     `json:"progress_phase,omitempty"`
	ProgressMessage   string     `json:"progress_message,omitempty"`
	ProgressUpdatedAt *time.Time `json:"progress_updated_at,omitempty"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	FinishedAt        *time.Time `json:"finished_at,omitempty"`
	RelatedType       string     `json:"related_type,omitempty"`
	RelatedID         *int64     `json:"related_id,omitempty"`
	ResultRef         string     `json:"result_ref,omitempty"`
	ResultSummary     string     `json:"result_summary,omitempty"`
	ErrorMessage      string     `json:"error_message,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type TriggerScheduledJobResponse struct {
	Run *ScheduledJobRunItem `json:"run"`
}
