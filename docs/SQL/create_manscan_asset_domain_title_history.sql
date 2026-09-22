CREATE TABLE `manscan_asset_domain_title_history` (
                                                     `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                                     `domain` VARCHAR(255) NOT NULL COMMENT '域名资产地址，格式为 domain:port 或 ip:port',
                                                     `history_title` VARCHAR(255) NOT NULL COMMENT '历史title，非空字符串',
                                                     `first_title_created_at` DATETIME NOT NULL COMMENT '首次title创建时间',
                                                     `latest_title_alive_at` DATE NOT NULL COMMENT '最新title存活日期',

                                                     PRIMARY KEY (`id`),
                                                     UNIQUE KEY `uk_domain_history_title` (`domain`, `history_title`),
                                                     KEY `idx_domain` (`domain`),
                                                     KEY `idx_latest_title_alive_at` (`latest_title_alive_at`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='域名历史title表';
