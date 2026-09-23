CREATE TABLE `manscan_asset_host` (
                                      `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                      `ip_address` VARCHAR(45) NOT NULL COMMENT 'IP地址',
                                      `region` VARCHAR(100) DEFAULT NULL COMMENT '区域',
                                      `owner` VARCHAR(100) DEFAULT NULL COMMENT '负责人',
                                      `os_type` VARCHAR(64) DEFAULT NULL COMMENT '操作系统类型',
                                      `os_version` VARCHAR(128) DEFAULT NULL COMMENT '操作系统版本',
                                      `scan_created_at` DATETIME NOT NULL COMMENT '扫描创建时间',
                                      `last_alive_at` DATETIME DEFAULT NULL COMMENT '上次扫描存活时间',

                                      `manual_note` TEXT DEFAULT NULL COMMENT '人工注释',
                                      `is_alive` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否存活：0否，1是',
                                      `related_domains` longtext DEFAULT NULL COMMENT '主机关联的域名资产，多个用英文逗号分隔',

                                      PRIMARY KEY (`id`),
                                      UNIQUE KEY `uk_ip_address` (`ip_address`),
                                      KEY `idx_region` (`region`),
                                      KEY `idx_owner` (`owner`),
                                      KEY `idx_is_alive` (`is_alive`),
                                      KEY `idx_last_alive_at` (`last_alive_at`),
                                      KEY `idx_scan_created_at` (`scan_created_at`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='主机资产表';
