CREATE TABLE `manscan_user_settings` (
                                        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                        `user_id` BIGINT UNSIGNED NOT NULL COMMENT '用户ID',
                                        `theme` VARCHAR(32) NOT NULL DEFAULT 'cartoon' COMMENT '主题标识',
                                        `dark_mode_enabled` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否开启深色模式',
                                        `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                                        `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                                        PRIMARY KEY (`id`),
                                        UNIQUE KEY `uk_user_id` (`user_id`),
                                        CONSTRAINT `fk_manscan_user_settings_user_id` FOREIGN KEY (`user_id`) REFERENCES `manscan_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ManScan用户设置表';
