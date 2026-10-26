CREATE TABLE `manscan_scheduled_jobs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '定时任务主键',
    `name` VARCHAR(128) NOT NULL COMMENT '任务名称',
    `description` VARCHAR(512) NOT NULL DEFAULT '' COMMENT '任务描述',
    `output_description` VARCHAR(512) NOT NULL DEFAULT '' COMMENT '任务产出内容描述',
    `job_type` VARCHAR(64) NOT NULL COMMENT '任务类型，对应服务端 JobHandler.Type()',
    `cron_expr` VARCHAR(64) NOT NULL COMMENT 'Cron 表达式',
    `timezone` VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai' COMMENT 'Cron 时区',
    `enabled` TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否启用',
    `api_key_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '关联 manscan_third_party_api_keys.id',
    `config_json` JSON NOT NULL COMMENT '任务配置，由具体任务类型解释',
    `concurrency_policy` VARCHAR(16) NOT NULL DEFAULT 'forbid' COMMENT 'forbid 或 allow',
    `timeout_seconds` INT UNSIGNED NOT NULL DEFAULT 300 COMMENT '单次执行超时，0 表示不限制',
    `next_run_at` DATETIME DEFAULT NULL COMMENT '下一次计划执行时间',
    `last_run_at` DATETIME DEFAULT NULL COMMENT '最近一次执行开始时间',
    `last_status` VARCHAR(32) NOT NULL DEFAULT '' COMMENT '最近一次执行状态',
    `last_error` VARCHAR(1024) NOT NULL DEFAULT '' COMMENT '最近一次错误',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    KEY `idx_scheduled_jobs_enabled` (`enabled`),
    KEY `idx_scheduled_jobs_api_key_id` (`api_key_id`),
    CONSTRAINT `fk_scheduled_jobs_api_key_id`
        FOREIGN KEY (`api_key_id`) REFERENCES `manscan_third_party_api_keys` (`id`)
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ManScan通用定时任务定义';
