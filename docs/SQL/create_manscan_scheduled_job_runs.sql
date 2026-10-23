CREATE TABLE `manscan_scheduled_job_runs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '执行记录主键',
    `job_id` BIGINT UNSIGNED NOT NULL COMMENT '定时任务ID',
    `trigger_type` VARCHAR(16) NOT NULL COMMENT 'schedule 或 manual',
    `fire_key` VARCHAR(128) NOT NULL COMMENT '本次触发唯一标识',
    `status` VARCHAR(32) NOT NULL COMMENT 'queued、running、success、failed、timeout、skipped、cancelled',
    `progress_current` BIGINT NOT NULL DEFAULT 0 COMMENT '当前进度',
    `progress_total` BIGINT NOT NULL DEFAULT 0 COMMENT '进度总量，0 表示未知',
    `progress_phase` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '进度阶段',
    `progress_message` VARCHAR(512) NOT NULL DEFAULT '' COMMENT '进度说明',
    `progress_updated_at` DATETIME DEFAULT NULL COMMENT '进度更新时间',
    `started_at` DATETIME DEFAULT NULL COMMENT '开始时间',
    `finished_at` DATETIME DEFAULT NULL COMMENT '结束时间',
    `related_type` VARCHAR(32) NOT NULL DEFAULT '' COMMENT '关联业务类型，预留',
    `related_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '关联业务ID，预留',
    `result_ref` VARCHAR(1024) NOT NULL DEFAULT '' COMMENT '结果引用，预留',
    `result_summary` JSON DEFAULT NULL COMMENT '结果摘要，预留',
    `error_message` VARCHAR(2048) NOT NULL DEFAULT '' COMMENT '错误信息',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_scheduled_job_runs_fire_key` (`fire_key`),
    KEY `idx_scheduled_job_runs_job_id_created_at` (`job_id`, `created_at`),
    KEY `idx_scheduled_job_runs_job_id_status` (`job_id`, `status`),
    CONSTRAINT `fk_scheduled_job_runs_job_id`
        FOREIGN KEY (`job_id`) REFERENCES `manscan_scheduled_jobs` (`id`)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ManScan定时任务执行记录与进度';
