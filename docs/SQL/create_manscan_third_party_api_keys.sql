CREATE TABLE `manscan_third_party_api_keys` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
    `encrypted_key` VARCHAR(1024) NOT NULL COMMENT 'AES-GCM 加密后的第三方平台 API Key',
    `platform_url` VARCHAR(2048) NOT NULL COMMENT '第三方平台地址 URL',
    `rate_limit_per_minute` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '每分钟请求次数，0 表示不限制',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '新增时间',
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    `description` VARCHAR(512) NOT NULL DEFAULT '' COMMENT '作用描述',

    PRIMARY KEY (`id`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='ManScan第三方API Key配置表';
