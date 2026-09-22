CREATE TABLE `manscan_asset_host_port` (
                                           `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                           `ip_address` VARCHAR(45) NOT NULL COMMENT 'IP地址',
                                           `region` VARCHAR(100) DEFAULT NULL COMMENT '区域',
                                           `last_alive_at` DATETIME DEFAULT NULL COMMENT '主机端口上次存活时间',
                                           `port_created_at` DATETIME NOT NULL COMMENT '主机端口创建时间',
                                           `port_protocol` VARCHAR(32) NOT NULL COMMENT '端口协议',
                                           `port_number` SMALLINT UNSIGNED NOT NULL COMMENT '端口数字',
                                           `service_name` VARCHAR(128) DEFAULT NULL COMMENT '端口服务名称',
                                           `app_name` VARCHAR(255) DEFAULT NULL COMMENT '端口应用名称',
                                           `app_version` VARCHAR(128) DEFAULT NULL COMMENT '端口应用版本',
                                           `is_alive` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否存活：0否，1是',
                                           `has_vulnerability` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '端口是否存在漏洞：0否，1是',
                                           `is_high_risk_port` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否是高危端口：0否，1是',

                                           PRIMARY KEY (`id`),
                                           UNIQUE KEY `uk_ip_protocol_port` (`ip_address`, `port_protocol`, `port_number`),
                                           KEY `idx_ip_address` (`ip_address`),
                                           KEY `idx_region` (`region`),
                                           KEY `idx_last_alive_at` (`last_alive_at`),
                                           KEY `idx_port_created_at` (`port_created_at`),
                                           KEY `idx_port_number` (`port_number`),
                                           KEY `idx_service_name` (`service_name`),
                                           KEY `idx_app_name` (`app_name`),
                                           KEY `idx_is_alive` (`is_alive`),
                                           KEY `idx_has_vulnerability` (`has_vulnerability`),
                                           KEY `idx_is_high_risk_port` (`is_high_risk_port`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='主机端口资产表';
