package dto

import (
	"time"

	"ManScan/server/internal/pkg/scanruntime"
)

type CreateScanTaskRequest struct {
	Name                          string   `json:"name"`
	Description                   string   `json:"description"`
	CreatedBy                     string   `json:"created_by"`
	Targets                       []string `json:"targets"`
	InlineTargetsList             string   `json:"inline_targets_list"`
	ExcludeTargets                []string `json:"exclude_targets"`
	ScanAllIPs                    bool     `json:"scan_all_ips"`
	IPVersion                     []string `json:"ip_version"`
	InputFileMode                 string   `json:"input_file_mode"`
	NewTemplates                  bool     `json:"new_templates"`
	AutomaticScan                 bool     `json:"automatic_scan"`
	DAST                          bool     `json:"dast"`
	EnableCodeTemplates           bool     `json:"enable_code_templates"`
	EnableFileTemplates           bool     `json:"enable_file_templates"`
	EnableGlobalMatchersTemplates bool     `json:"enable_global_matchers_templates"`
	Tags                          []string `json:"tags"`
	IncludeIDs                    []string `json:"include_ids"`
	Severities                    []string `json:"severities"`
	Protocols                     []string `json:"protocols"`
	StoreResponse                 bool     `json:"store_response"`
	Timestamp                     bool     `json:"timestamp"`
	MatcherStatus                 bool     `json:"matcher_status"`
	CustomHeaders                 []string `json:"custom_headers"`
	Vars                          []string `json:"vars"`
	FollowRedirects               bool     `json:"follow_redirects"`
	FollowHostRedirects           bool     `json:"follow_host_redirects"`
	MaxRedirects                  int      `json:"max_redirects"`
	DisableRedirects              bool     `json:"disable_redirects"`
	OfflineHTTP                   bool     `json:"offline_http"`
	ForceAttemptHTTP2             bool     `json:"force_attempt_http2"`
	SNI                           string   `json:"sni"`
	AllowLocalFileAccess          bool     `json:"allow_local_file_access"`
	AttackType                    string   `json:"attack_type"`
	SourceIP                      string   `json:"source_ip"`
	ResponseReadSize              int      `json:"response_read_size"`
	ResponseSaveSize              int      `json:"response_save_size"`
	TLSImpersonate                bool     `json:"tls_impersonate"`
	RateLimit                     int      `json:"rate_limit"`
	RateLimitDuration             int64    `json:"rate_limit_duration"`
	BulkSize                      int      `json:"bulk_size"`
	TemplateThreads               int      `json:"template_threads"`
	HeadlessBulkSize              int      `json:"headless_bulk_size"`
	HeadlessTemplateThreads       int      `json:"headless_template_threads"`
	JSConcurrency                 int      `json:"js_concurrency"`
	PayloadConcurrency            int      `json:"payload_concurrency"`
	ProbeConcurrency              int      `json:"probe_concurrency"`
	Timeout                       int      `json:"timeout"`
	Retries                       int      `json:"retries"`
	MaxHostError                  int      `json:"max_host_error"`
	NoHostErrors                  bool     `json:"no_host_errors"`
	Project                       bool     `json:"project"`
	ProjectPath                   string   `json:"project_path"`
	ScanStrategy                  string   `json:"scan_strategy"`
	DisableHTTPProbe              bool     `json:"disable_http_probe"`
	Headless                      bool     `json:"headless"`
	PageTimeout                   int      `json:"page_timeout"`
	ShowBrowser                   bool     `json:"show_browser"`
	HeadlessOptionalArguments     []string `json:"headless_optional_arguments"`
	UseInstalledChrome            bool     `json:"use_installed_chrome"`
	CDPEndpoint                   string   `json:"cdp_endpoint"`
	ShowActions                   bool     `json:"show_actions"`
	Proxy                         []string `json:"proxy"`
	ProxyInternal                 bool     `json:"proxy_internal"`
	EnableProgressBar             bool     `json:"enable_progress_bar"`
	StatsInterval                 int      `json:"stats_interval"`
	MetricsPort                   int      `json:"metrics_port"`
	HTTPStats                     bool     `json:"http_stats"`
}

type ListScanTasksQuery struct {
	Page           int
	PageSize       int
	Keyword        string
	Statuses       []string
	ScanStrategies []string
	CreatedBy      string
	HasHighRisk    bool
}

type ListScanTaskNameOptionsQuery struct {
	Page     int
	PageSize int
	Keyword  string
}

type ScanTaskNameOption struct {
	Name string `json:"name"`
}

type ScanTaskListItem struct {
	ID              int64      `json:"id"`
	TaskNo          string     `json:"task_no"`
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	Status          string     `json:"status"`
	CreatedBy       string     `json:"created_by"`
	ScanStrategy    string     `json:"scan_strategy"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	CriticalCount   int        `json:"critical_count"`
	HighCount       int        `json:"high_count"`
	MediumCount     int        `json:"medium_count"`
	LowCount        int        `json:"low_count"`
	InfoCount       int        `json:"info_count"`
	TechCount       int        `json:"tech_count"`
	PluginCount     int        `json:"plugin_count"`
	TargetCount     int        `json:"target_count"`
	TotalRequests   int64      `json:"total_requests"`
	RealRequests    int64      `json:"real_requests"`
	ProgressPercent float64    `json:"progress_percent"`
	DurationSeconds int64      `json:"duration_seconds"`
	LastMessage     string     `json:"last_message,omitempty"`
}

type ScanTaskStats struct {
	Total         int64 `json:"total"`
	Running       int64 `json:"running"`
	SavedRequests int64 `json:"saved_requests"`
}

type ScanTaskSummary struct {
	ID            int64      `json:"id"`
	TaskNo        string     `json:"task_no"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Status        string     `json:"status"`
	CreatedBy     string     `json:"created_by"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	CriticalCount int        `json:"critical_count"`
	HighCount     int        `json:"high_count"`
	MediumCount   int        `json:"medium_count"`
	LowCount      int        `json:"low_count"`
	InfoCount     int        `json:"info_count"`
	TechCount     int        `json:"tech_count"`
	PluginCount   int        `json:"plugin_count"`
	TargetCount   int        `json:"target_count"`
}

type CancelScanTaskResponse struct {
	TaskID          int64  `json:"task_id"`
	Status          string `json:"status"`
	CancelRequested bool   `json:"cancel_requested"`
}

type PauseScanTaskResponse struct {
	TaskID         int64  `json:"task_id"`
	Status         string `json:"status"`
	PauseRequested bool   `json:"pause_requested"`
}

type ResumeScanTaskResponse struct {
	TaskID          int64  `json:"task_id"`
	Status          string `json:"status"`
	ResumeRequested bool   `json:"resume_requested"`
}

type DeleteScanTaskRequest struct {
	ID  *int64  `json:"id,omitempty"`
	IDs []int64 `json:"ids,omitempty"`
}

type DeleteScanTaskResponse struct {
	IDs          []int64 `json:"ids"`
	DeletedCount int64   `json:"deleted_count"`
}

type GetScanTaskResponse struct {
	Task     ScanTaskSummary                  `json:"task"`
	Progress scanruntime.TaskProgressSnapshot `json:"progress"`
}

type ScanTaskLogsResponse struct {
	Task       ScanTaskSummary                  `json:"task"`
	Progress   scanruntime.TaskProgressSnapshot `json:"progress"`
	Events     []scanruntime.TaskLogEvent       `json:"events"`
	NextOffset int64                            `json:"next_offset"`
	HasMore    bool                             `json:"has_more"`
}

type ScanTaskResponseArchive struct {
	Path     string `json:"-"`
	FileName string `json:"file_name"`
	Size     int64  `json:"size"`
}
