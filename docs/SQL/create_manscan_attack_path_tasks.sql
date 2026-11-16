CREATE TABLE `manscan_attack_path_tasks` (
    `id` CHAR(32) NOT NULL COMMENT '随机任务ID，32个十六进制字符，用于轮询、下载及任务目录命名',
    `owner_user_id` BIGINT NOT NULL COMMENT '提交用户ID，用于查询、取消及下载时校验任务归属',
    `status` VARCHAR(16) NOT NULL COMMENT '任务状态：queued排队、running处理中、completed成功、failed失败、cancelled已取消',
    `output_file_name` VARCHAR(96) NULL COMMENT '结果文件名，格式为output.<执行token>.txt；任务完成后用于定位本地结果文件',
    `total` INT NOT NULL COMMENT '清理空行并去重后的待处理路径总数',
    `processed` INT NOT NULL DEFAULT 0 COMMENT '已提交分类结果的路径数，用于计算任务进度',
    `kept` INT NOT NULL DEFAULT 0 COMMENT '已处理路径中保留的正常路径数，成功完成时为结果TXT的路径数',
    `error_message` VARCHAR(512) NOT NULL DEFAULT '' COMMENT '对外失败提示，正常为空，不保存密钥或完整模型对话',
    `lease_token` CHAR(32) NOT NULL DEFAULT '' COMMENT '本次执行的随机租约凭证，续期及提交结果时校验，任务结束时清空',
    `lease_until` DATETIME NULL COMMENT '执行租约到期时间，过期的running任务可重新领取，任务结束时置NULL',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '任务记录创建时间',
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '记录最近更新时间，包括状态、进度及租约心跳更新',
    `finished_at` DATETIME NULL COMMENT '任务成功、失败或取消的结束时间，排队及处理中为NULL',
    PRIMARY KEY (`id`),
    KEY `idx_attack_path_tasks_owner_created` (`owner_user_id`, `created_at`),
    KEY `idx_attack_path_tasks_status_created` (`status`, `created_at`),
    KEY `idx_attack_path_tasks_lease_until` (`lease_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='攻击路径TXT过滤任务状态、进度及结果文件引用';
