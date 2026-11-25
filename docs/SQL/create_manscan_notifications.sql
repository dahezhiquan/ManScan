CREATE TABLE IF NOT EXISTS `manscan_notifications` (
    `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT '主键ID',
    `name` VARCHAR(100) NOT NULL COMMENT '通知名称',
    `enabled` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '通知开关：0关闭，1开启',
    `event` VARCHAR(32) NOT NULL COMMENT '触发事件，当前支持 scan_started（扫描任务发起）',
    `encrypted_webhook` TEXT NOT NULL COMMENT 'AES-GCM 加密后的飞书机器人 Webhook 地址',
    `style` VARCHAR(32) NOT NULL COMMENT '标题栏颜色：blue蓝、orange橙、purple紫、red红、green绿、yellow黄、grey灰',
    `created_at` DATETIME(3) NULL DEFAULT NULL COMMENT '创建时间，由服务端写入',
    `updated_at` DATETIME(3) NULL DEFAULT NULL COMMENT '更新时间，由服务端维护',

    PRIMARY KEY (`id`),
    KEY `idx_notification_event_enabled` (`event`, `enabled`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='ManScan飞书群通知配置表';
