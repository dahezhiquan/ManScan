CREATE TABLE `manscan_auth_challenges` (
                                           `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                           `challenge_id` VARCHAR(64) NOT NULL COMMENT '验证码挑战ID',
                                           `challenge_type` VARCHAR(32) NOT NULL COMMENT '验证码类型',
                                           `target_angle` DOUBLE NOT NULL COMMENT '轨道目标角度',
                                           `answer_tolerance` DOUBLE NOT NULL COMMENT '允许角度误差',
                                           `scene_seed` BIGINT NOT NULL COMMENT '前端场景渲染种子',
                                           `client_ip` VARCHAR(64) DEFAULT NULL COMMENT '生成验证码的客户端IP',
                                           `expires_at` DATETIME NOT NULL COMMENT '过期时间',
                                           `used_at` DATETIME DEFAULT NULL COMMENT '使用时间',
                                           `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                                           `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                                           PRIMARY KEY (`id`),
                                           UNIQUE KEY `uk_challenge_id` (`challenge_id`),
                                           KEY `idx_expires_at` (`expires_at`),
                                           KEY `idx_used_at` (`used_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ManScan登录验证码挑战表';
