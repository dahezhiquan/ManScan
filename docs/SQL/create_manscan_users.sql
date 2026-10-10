CREATE TABLE `manscan_users` (
                                 `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                 `username` VARCHAR(64) NOT NULL COMMENT '登录用户名',
                                 `password_hash` VARCHAR(255) NOT NULL COMMENT 'bcrypt密码哈希',
                                 `display_name` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '展示名称',
                                 `role` VARCHAR(32) NOT NULL DEFAULT 'user' COMMENT '角色: admin/user',
                                 `status` ENUM('enabled', 'disabled', 'locked') NOT NULL DEFAULT 'enabled' COMMENT '状态: enabled=启用, disabled=禁用, locked=锁定',
                                 `failed_login_attempts` INT NOT NULL DEFAULT 0 COMMENT '连续登录失败次数',
                                 `last_login_at` DATETIME DEFAULT NULL COMMENT '最后登录时间',
                                 `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                                 `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                                 PRIMARY KEY (`id`),
                                 UNIQUE KEY `uk_username` (`username`),
                                 KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ManScan用户表';
