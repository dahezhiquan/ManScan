CREATE TABLE `manscan_user_sessions` (
                                         `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                         `user_id` BIGINT UNSIGNED NOT NULL COMMENT '用户ID',
                                         `token_id` VARCHAR(64) NOT NULL COMMENT 'JWT jti',
                                         `token_hash` CHAR(64) NOT NULL COMMENT '访问令牌SHA-256哈希',
                                         `client_ip` VARCHAR(64) DEFAULT NULL COMMENT '登录客户端IP',
                                         `user_agent` VARCHAR(500) DEFAULT NULL COMMENT '登录客户端User-Agent',
                                         `expires_at` DATETIME NOT NULL COMMENT '过期时间',
                                         `revoked_at` DATETIME DEFAULT NULL COMMENT '主动退出或吊销时间',
                                         `last_seen_at` DATETIME DEFAULT NULL COMMENT '最近一次鉴权时间',
                                         `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                                         `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                                         PRIMARY KEY (`id`),
                                         UNIQUE KEY `uk_token_id` (`token_id`),
                                         KEY `idx_user_id` (`user_id`),
                                         KEY `idx_expires_at` (`expires_at`),
                                         KEY `idx_revoked_at` (`revoked_at`),
                                         CONSTRAINT `fk_manscan_user_sessions_user_id` FOREIGN KEY (`user_id`) REFERENCES `manscan_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ManScan用户会话表';
