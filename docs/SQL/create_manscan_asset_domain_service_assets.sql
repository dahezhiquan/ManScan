CREATE TABLE `manscan_asset_domain_service_assets` (
                                                       `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                                       `domain` VARCHAR(255) NOT NULL COMMENT '域名资产地址，格式为 domain:port 或 ip:port',
                                                       `app_name` VARCHAR(255) NOT NULL COMMENT '应用名称',
                                                       `app_version` VARCHAR(128) NOT NULL COMMENT '应用版本',
                                                       `last_found_at` DATETIME NOT NULL COMMENT '最近发现时间',
                                                       `first_found_at` DATETIME NOT NULL COMMENT '首次发现时间',
                                                       `is_alive` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否存活：0否，1是',

                                                       PRIMARY KEY (`id`),
                                                       UNIQUE KEY `uk_domain_app_name` (`domain`, `app_name`),
                                                       KEY `idx_domain` (`domain`),
                                                       KEY `idx_is_alive` (`is_alive`),
                                                       KEY `idx_last_found_at` (`last_found_at`),
                                                       KEY `idx_first_found_at` (`first_found_at`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='域名服务资产表';
