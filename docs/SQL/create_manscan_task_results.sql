CREATE TABLE `manscan_task_results` (
                                        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                        `task_id` BIGINT UNSIGNED NOT NULL COMMENT '任务ID',
                                        `task_name` VARCHAR(128) NOT NULL COMMENT '任务名称',
                                        `critical_count` INT NOT NULL DEFAULT 0 COMMENT '严重漏洞数量',
                                        `high_count` INT NOT NULL DEFAULT 0 COMMENT '高危漏洞数量',
                                        `medium_count` INT NOT NULL DEFAULT 0 COMMENT '中危漏洞数量',
                                        `low_count` INT NOT NULL DEFAULT 0 COMMENT '低危漏洞数量',
                                        `info_count` INT NOT NULL DEFAULT 0 COMMENT '信息漏洞数量',
                                        `plugin_count` INT NOT NULL DEFAULT 0 COMMENT '漏洞插件数量',
                                        `target_count` INT NOT NULL DEFAULT 0 COMMENT '目标数量',
                                        `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                                        `finished_at` DATETIME DEFAULT NULL COMMENT '结束时间',
                                        PRIMARY KEY (`id`),
                                        UNIQUE KEY `uk_task_id` (`task_id`),
                                        KEY `idx_task_name` (`task_name`),
                                        KEY `idx_created_at` (`created_at`),
                                        KEY `idx_finished_at` (`finished_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='任务结果表';
