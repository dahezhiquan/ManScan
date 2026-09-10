package entity

import "time"

type ScanTask struct {
	ID                            int64      `gorm:"column:id;primaryKey;autoIncrement"`
	TaskNo                        string     `gorm:"column:task_no"`
	Name                          string     `gorm:"column:name"`
	Description                   *string    `gorm:"column:description"`
	Status                        string     `gorm:"column:status"`
	CreatedBy                     string     `gorm:"column:created_by"`
	StartedAt                     *time.Time `gorm:"column:started_at"`
	FinishedAt                    *time.Time `gorm:"column:finished_at"`
	Targets                       string     `gorm:"column:targets"`
	InlineTargetsList             *string    `gorm:"column:inline_targets_list"`
	ExcludeTargets                string     `gorm:"column:exclude_targets"`
	ScanAllIPs                    bool       `gorm:"column:scan_all_ips"`
	IPVersion                     string     `gorm:"column:ip_version"`
	InputFileMode                 string     `gorm:"column:input_file_mode"`
	NewTemplates                  bool       `gorm:"column:new_templates"`
	AutomaticScan                 bool       `gorm:"column:automatic_scan"`
	DAST                          bool       `gorm:"column:dast"`
	EnableCodeTemplates           bool       `gorm:"column:enable_code_templates"`
	EnableFileTemplates           bool       `gorm:"column:enable_file_templates"`
	EnableGlobalMatchersTemplates bool       `gorm:"column:enable_global_matchers_templates"`
	Tags                          string     `gorm:"column:tags"`
	IncludeIDs                    string     `gorm:"column:include_ids"`
	Severities                    string     `gorm:"column:severities"`
	Protocols                     string     `gorm:"column:protocols"`
	StoreResponse                 bool       `gorm:"column:store_response"`
	Timestamp                     bool       `gorm:"column:timestamp"`
	MatcherStatus                 bool       `gorm:"column:matcher_status"`
	CustomHeaders                 string     `gorm:"column:custom_headers"`
	Vars                          string     `gorm:"column:vars"`
	InteractshServer              *string    `gorm:"column:interactsh_server"`
	InteractshToken               *string    `gorm:"column:interactsh_token"`
	NoInteractsh                  bool       `gorm:"column:no_interactsh"`
	FollowRedirects               bool       `gorm:"column:follow_redirects"`
	FollowHostRedirects           bool       `gorm:"column:follow_host_redirects"`
	MaxRedirects                  int        `gorm:"column:max_redirects"`
	DisableRedirects              bool       `gorm:"column:disable_redirects"`
	OfflineHTTP                   bool       `gorm:"column:offline_http"`
	ForceAttemptHTTP2             bool       `gorm:"column:force_attempt_http2"`
	SNI                           *string    `gorm:"column:sni"`
	AllowLocalFileAccess          bool       `gorm:"column:allow_local_file_access"`
	AttackType                    *string    `gorm:"column:attack_type"`
	SourceIP                      *string    `gorm:"column:source_ip"`
	ResponseReadSize              int        `gorm:"column:response_read_size"`
	ResponseSaveSize              int        `gorm:"column:response_save_size"`
	TLSImpersonate                bool       `gorm:"column:tls_impersonate"`
	RateLimit                     int        `gorm:"column:rate_limit"`
	RateLimitDuration             int64      `gorm:"column:rate_limit_duration"`
	BulkSize                      int        `gorm:"column:bulk_size"`
	TemplateThreads               int        `gorm:"column:template_threads"`
	HeadlessBulkSize              int        `gorm:"column:headless_bulk_size"`
	HeadlessTemplateThreads       int        `gorm:"column:headless_template_threads"`
	JSConcurrency                 int        `gorm:"column:js_concurrency"`
	PayloadConcurrency            int        `gorm:"column:payload_concurrency"`
	ProbeConcurrency              int        `gorm:"column:probe_concurrency"`
	Timeout                       int        `gorm:"column:timeout"`
	Retries                       int        `gorm:"column:retries"`
	MaxHostError                  int        `gorm:"column:max_host_error"`
	NoHostErrors                  bool       `gorm:"column:no_host_errors"`
	Project                       bool       `gorm:"column:project"`
	ProjectPath                   *string    `gorm:"column:project_path"`
	ScanStrategy                  *string    `gorm:"column:scan_strategy"`
	DisableHTTPProbe              bool       `gorm:"column:disable_http_probe"`
	Headless                      bool       `gorm:"column:headless"`
	PageTimeout                   int        `gorm:"column:page_timeout"`
	ShowBrowser                   bool       `gorm:"column:show_browser"`
	HeadlessOptionalArguments     string     `gorm:"column:headless_optional_arguments"`
	UseInstalledChrome            bool       `gorm:"column:use_installed_chrome"`
	CDPEndpoint                   *string    `gorm:"column:cdp_endpoint"`
	ShowActions                   bool       `gorm:"column:show_actions"`
	Proxy                         string     `gorm:"column:proxy"`
	ProxyInternal                 bool       `gorm:"column:proxy_internal"`
	EnableProgressBar             bool       `gorm:"column:enable_progress_bar"`
	StatsInterval                 int        `gorm:"column:stats_interval"`
	MetricsPort                   int        `gorm:"column:metrics_port"`
	HTTPStats                     bool       `gorm:"column:http_stats"`
}

func (ScanTask) TableName() string {
	return "manscan_scan_tasks"
}
