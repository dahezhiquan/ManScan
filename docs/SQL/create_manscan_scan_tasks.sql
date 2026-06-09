CREATE TABLE `manscan_scan_tasks` (
    -- =========================
    -- 基础任务字段
    -- =========================
                                      `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                      `task_no` VARCHAR(64) NOT NULL COMMENT '任务编号',
                                      `name` VARCHAR(128) NOT NULL COMMENT '任务名称',
                                      `description` VARCHAR(255) DEFAULT NULL COMMENT '任务描述',
                                      `status` VARCHAR(32) NOT NULL DEFAULT 'pending' COMMENT '任务状态: pending/running/success/failed/cancelled',
                                      `created_by` VARCHAR(64) NOT NULL COMMENT '创建人',
                                      `started_at` DATETIME DEFAULT NULL COMMENT '扫描开始时间',
                                      `finished_at` DATETIME DEFAULT NULL COMMENT '扫描结束时间',

    -- =========================
    -- Target 输入组
    -- 对应 group: input / target-format
    -- =========================
                                      `targets` JSON DEFAULT NULL COMMENT '扫描目标列表，对应 -u/--target',
                                      `targets_file_path` VARCHAR(500) DEFAULT NULL COMMENT '扫描目标文件，对应 -l/--list',
                                      `inline_targets_list` LONGTEXT DEFAULT NULL COMMENT '多行内联目标，对应 --targets-inline',
                                      `exclude_targets` JSON DEFAULT NULL COMMENT '排除目标列表，对应 -eh/--exclude-hosts',
                                      `resume` VARCHAR(500) DEFAULT NULL COMMENT '恢复扫描文件，对应 --resume',
                                      `scan_all_ips` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否扫描域名所有IP，对应 -sa/--scan-all-ips',
                                      `ip_version` JSON DEFAULT NULL COMMENT 'IP版本列表，对应 -iv/--ip-version，值如 ["4","6"]',
                                      `input_file_mode` VARCHAR(32) NOT NULL DEFAULT 'list' COMMENT '输入文件模式，对应 -im/--input-mode',
                                      `vars_text_templating` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'YAML变量文本模板渲染，对应 -vtt/--vars-text-templating',
                                      `vars_file_paths` JSON DEFAULT NULL COMMENT '变量文件路径列表，对应 -vfp/--var-file-paths',

    -- =========================
    -- Templates 模板组
    -- =========================
                                      `new_templates` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '仅运行新增模板，对应 -nt/--new-templates',
                                      `automatic_scan` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '自动模板映射扫描，对应 -as/--automatic-scan',
                                      `ai_template_prompt` TEXT DEFAULT NULL COMMENT 'AI生成模板提示词，对应 -ai/--prompt',
                                      `enable_global_matchers_templates` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '启用全局匹配器模板，对应 -egm/--enable-global-matchers',

    -- =========================
    -- Filtering 过滤组
    -- =========================
                                      `tags` JSON DEFAULT NULL COMMENT '标签过滤，对应 --tags',
                                      `include_ids` JSON DEFAULT NULL COMMENT '模板ID过滤，对应 -id/--template-id',
                                      `severities` JSON DEFAULT NULL COMMENT '严重级别过滤，对应 -s/--severity',
                                      `protocols` JSON DEFAULT NULL COMMENT '协议类型过滤，对应 -pt/--type',

    -- =========================
    -- Output 输出组
    -- =========================
                                      `store_response` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '保存请求响应，对应 -sresp/--store-resp',
                                      `timestamp` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '输出时间戳，对应 -ts/--timestamp',
                                      `matcher_status` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '显示匹配器状态，对应 -ms/--matcher-status',
                                      `markdown_export_directory` VARCHAR(500) DEFAULT NULL COMMENT 'Markdown导出目录，对应 -me/--markdown-export',
                                      `sarif_export` VARCHAR(500) DEFAULT NULL COMMENT 'SARIF导出文件，对应 -se/--sarif-export',
                                      `json_export` VARCHAR(500) DEFAULT NULL COMMENT 'JSON导出文件，对应 -je/--json-export',
                                      `jsonl_export` VARCHAR(500) DEFAULT NULL COMMENT 'JSONL导出文件，对应 -jle/--jsonl-export',
                                      `pdf_export` VARCHAR(500) DEFAULT NULL COMMENT 'PDF导出文件，对应 -pe/--pdf-export',
                                      `redact` JSON DEFAULT NULL COMMENT '脱敏key列表，对应 -rd/--redact',

    -- =========================
    -- Configurations 配置组
    -- =========================
                                      `config_file` VARCHAR(500) DEFAULT NULL COMMENT '配置文件路径，对应 --config',
                                      `follow_redirects` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '跟随重定向，对应 -fr/--follow-redirects',
                                      `follow_host_redirects` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '仅同主机重定向，对应 -fhr/--follow-host-redirects',
                                      `max_redirects` INT NOT NULL DEFAULT 10 COMMENT '最大重定向次数，对应 -mr/--max-redirects',
                                      `disable_redirects` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '禁用重定向，对应 -dr/--disable-redirects',
                                      `custom_headers` JSON DEFAULT NULL COMMENT '自定义请求头，对应 -H/--header',
                                      `vars` JSON DEFAULT NULL COMMENT '运行时变量(key=value)，对应 -V/--var',
                                      `resolvers_file` VARCHAR(500) DEFAULT NULL COMMENT 'DNS解析器文件，对应 -r/--resolvers',
                                      `offline_http` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '被动HTTP模式，对应 --passive',
                                      `force_attempt_http2` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '强制HTTP2，对应 -fh2/--force-http2',
                                      `ztls` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '使用ztls，对应 --ztls',
                                      `sni` VARCHAR(255) DEFAULT NULL COMMENT 'SNI主机名，对应 --sni',
                                      `dialer_keep_alive` BIGINT DEFAULT 0 COMMENT 'keep alive时长(毫秒)，对应 -dka/--dialer-keep-alive',
                                      `allow_local_file_access` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '允许本地文件访问，对应 -lfa/--allow-local-file-access',
                                      `attack_type` VARCHAR(32) DEFAULT NULL COMMENT '攻击类型，对应 -at/--attack-type',
                                      `source_ip` VARCHAR(64) DEFAULT NULL COMMENT '源IP，对应 -sip/--source-ip',
                                      `response_read_size` INT NOT NULL DEFAULT 0 COMMENT '读取响应字节上限，对应 -rsr/--response-size-read',
                                      `response_save_size` INT NOT NULL DEFAULT 1048576 COMMENT '保存响应字节上限，对应 -rss/--response-size-save',
                                      `tls_impersonate` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'TLS指纹伪装，对应 -tlsi/--tls-impersonate',
                                      `http_api_endpoint` VARCHAR(500) DEFAULT NULL COMMENT 'HTTP API端点，对应 -hae/--http-api-endpoint',

    -- =========================
    -- Interactsh 组
    -- =========================
                                      `interactsh_url` VARCHAR(500) DEFAULT NULL COMMENT 'Interactsh服务地址，对应 -iserver/--interactsh-server',
                                      `interactsh_token` VARCHAR(255) DEFAULT NULL COMMENT 'Interactsh令牌，对应 -itoken/--interactsh-token',
                                      `interactions_cache_size` INT NOT NULL DEFAULT 5000 COMMENT '交互缓存大小，对应 --interactions-cache-size',
                                      `interactions_eviction` INT NOT NULL DEFAULT 60 COMMENT '交互缓存淘汰时间(秒)，对应 --interactions-eviction',
                                      `interactions_poll_duration` INT NOT NULL DEFAULT 5 COMMENT '交互轮询间隔(秒)，对应 --interactions-poll-duration',
                                      `interactions_cool_down_period` INT NOT NULL DEFAULT 5 COMMENT '交互冷却时间(秒)，对应 --interactions-cooldown-period',

    -- =========================
    -- Fuzzing / DAST 组
    -- =========================
                                      `fuzzing_type` VARCHAR(32) DEFAULT NULL COMMENT 'fuzz类型，对应 -ft/--fuzzing-type',
                                      `fuzzing_mode` VARCHAR(32) DEFAULT NULL COMMENT 'fuzz模式，对应 -fm/--fuzzing-mode',
                                      `dast` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '启用DAST，对应 --dast',
                                      `dast_server` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'DAST服务模式，对应 -dts/--dast-server',
                                      `dast_report` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'DAST报告，对应 -dtr/--dast-report',
                                      `dast_server_token` VARCHAR(255) DEFAULT NULL COMMENT 'DAST服务token，对应 -dtst/--dast-server-token',
                                      `dast_server_address` VARCHAR(255) DEFAULT 'localhost:9055' COMMENT 'DAST服务监听地址，对应 -dtsa/--dast-server-address',
                                      `fuzz_param_frequency` INT NOT NULL DEFAULT 10 COMMENT 'fuzz参数频率，对应 --fuzz-param-frequency',
                                      `fuzz_aggression_level` VARCHAR(16) NOT NULL DEFAULT 'low' COMMENT 'fuzz激进程度，对应 -fa/--fuzz-aggression',
                                      `scope` JSON DEFAULT NULL COMMENT 'fuzz范围，对应 -cs/--fuzz-scope',
                                      `out_of_scope` JSON DEFAULT NULL COMMENT 'fuzz排除范围，对应 -cos/--fuzz-out-scope',

    -- =========================
    -- Uncover 组
    -- =========================
                                      `uncover` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '启用Uncover，对应 -uc/--uncover',
                                      `uncover_query` JSON DEFAULT NULL COMMENT 'Uncover查询语句，对应 -uq/--uncover-query',
                                      `uncover_engine` JSON DEFAULT NULL COMMENT 'Uncover引擎，对应 -ue/--uncover-engine',
                                      `uncover_field` VARCHAR(64) DEFAULT 'ip:port' COMMENT 'Uncover返回字段，对应 -uf/--uncover-field',
                                      `uncover_limit` INT NOT NULL DEFAULT 100 COMMENT 'Uncover最大结果，对应 -ul/--uncover-limit',
                                      `uncover_rate_limit` INT NOT NULL DEFAULT 60 COMMENT 'Uncover速率限制(每分钟)，对应 -ur/--uncover-ratelimit',

    -- =========================
    -- Rate Limit / Concurrency 组
    -- =========================
                                      `rate_limit` INT NOT NULL DEFAULT 150 COMMENT '每秒请求数，对应 -rl/--rate-limit',
                                      `rate_limit_duration` BIGINT NOT NULL DEFAULT 1000 COMMENT '速率窗口(毫秒)，对应 -rld/--rate-limit-duration',
                                      `bulk_size` INT NOT NULL DEFAULT 25 COMMENT '每模板并行主机数，对应 -bs/--bulk-size',
                                      `template_threads` INT NOT NULL DEFAULT 25 COMMENT '模板并发数，对应 -c/--concurrency',
                                      `headless_bulk_size` INT NOT NULL DEFAULT 10 COMMENT '无头模板并行主机数，对应 -hbs/--headless-bulk-size',
                                      `headless_template_threads` INT NOT NULL DEFAULT 10 COMMENT '无头模板并发，对应 -headc/--headless-concurrency',
                                      `js_concurrency` INT NOT NULL DEFAULT 120 COMMENT 'JS并发，对应 -jsc/--js-concurrency',
                                      `payload_concurrency` INT NOT NULL DEFAULT 25 COMMENT 'Payload并发，对应 -pc/--payload-concurrency',
                                      `probe_concurrency` INT NOT NULL DEFAULT 50 COMMENT 'HTTP探测并发，对应 -prc/--probe-concurrency',
    -- =========================
    -- Optimization 组
    -- =========================
                                      `timeout` INT NOT NULL DEFAULT 10 COMMENT '请求超时(秒)，对应 --timeout',
                                      `retries` INT NOT NULL DEFAULT 1 COMMENT '重试次数，对应 --retries',
                                      `max_host_error` INT NOT NULL DEFAULT 30 COMMENT '最大主机错误数，对应 -mhe/--max-host-error',
                                      `no_host_errors` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '禁用主机错误跳过，对应 -nmhe/--no-mhe',
                                      `project` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '启用Project缓存，对应 --project',
                                      `project_path` VARCHAR(500) DEFAULT NULL COMMENT 'Project缓存路径，对应 --project-path',
                                      `scan_strategy` VARCHAR(32) DEFAULT 'auto' COMMENT '扫描策略，对应 -ss/--scan-strategy',
                                      `disable_http_probe` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '禁用httpx探测，对应 -nh/--no-httpx',

    -- =========================
    -- Headless 组
    -- =========================
                                      `headless` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '启用无头浏览器，对应 --headless',
                                      `page_timeout` INT NOT NULL DEFAULT 20 COMMENT '页面超时(秒)，对应 --page-timeout',
                                      `show_browser` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '显示浏览器，对应 -sb/--show-browser',
                                      `headless_optional_arguments` JSON DEFAULT NULL COMMENT '无头浏览器额外参数，对应 -ho/--headless-options',
                                      `use_installed_chrome` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '使用系统Chrome，对应 -sc/--system-chrome',
                                      `cdp_endpoint` VARCHAR(500) DEFAULT NULL COMMENT '远程CDP端点，对应 -cdpe/--cdp-endpoint',
                                      `show_actions` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '列出headless动作，对应 -lha/--list-headless-action',

    -- =========================
    -- Debug 组
    -- =========================
                                      `proxy` JSON DEFAULT NULL COMMENT '代理列表，对应 -p/--proxy',
                                      `proxy_internal` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '内部请求也走代理，对应 -pi/--proxy-internal',
                                      `trace_log_file` VARCHAR(500) DEFAULT NULL COMMENT '请求跟踪日志，对应 -tlog/--trace-log',
                                      `error_log_file` VARCHAR(500) DEFAULT NULL COMMENT '错误日志，对应 -elog/--error-log',
                                      `enable_pprof` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '开启pprof，对应 -ep/--enable-pprof',
                                      `health_check` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '健康检查，对应 -hc/--health-check',

    -- =========================
    -- Update / Honeypot / Stats 组
    -- =========================
                                      `honeypot_detection` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '蜜罐检测，对应 -hpd/--honeypot-detect',
                                      `honeypot_threshold` INT NOT NULL DEFAULT 15 COMMENT '蜜罐阈值，对应 -hpt/--honeypot-threshold',
                                      `suppress_honeypot_results` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '抑制蜜罐结果，对应 -shp/--suppress-honeypot',
                                      `enable_progress_bar` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '统计进度展示，对应 --stats',
                                      `stats_interval` INT NOT NULL DEFAULT 5 COMMENT '统计间隔(秒)，对应 -si/--stats-interval',
                                      `metrics_port` INT NOT NULL DEFAULT 9092 COMMENT '监控端口，对应 -mp/--metrics-port',
                                      `http_stats` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'HTTP状态统计，对应 -hps/--http-stats',
                                      PRIMARY KEY (`id`),
                                      UNIQUE KEY `uk_task_no` (`task_no`),
                                      KEY `idx_status` (`status`),
                                      KEY `idx_created_by` (`created_by`),
                                      KEY `idx_started_at` (`started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ManScan扫描任务表';
