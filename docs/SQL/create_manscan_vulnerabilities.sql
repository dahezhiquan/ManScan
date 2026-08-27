CREATE TABLE `manscan_vulnerabilities` (
                                           `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',

                                           `template_id` VARCHAR(255) NOT NULL COMMENT '命中的漏洞模板ID',
                                           `vulnerability_name` VARCHAR(255) NOT NULL COMMENT '漏洞名称',

                                           `latest_scan_task_name` VARCHAR(255) NOT NULL COMMENT '命中漏洞的最近扫描任务名称',
                                           `latest_scan_task_id` VARCHAR(255) NOT NULL COMMENT '命中漏洞的最近扫描任务ID',

                                           `first_found_at` DATETIME NOT NULL COMMENT '漏洞初次发现时间',
                                           `last_found_at` DATETIME NOT NULL COMMENT '漏洞最近发现时间',
                                           `fixed_at` DATETIME DEFAULT NULL COMMENT '漏洞修复时间',

                                           `status` VARCHAR(32) NOT NULL DEFAULT 'unreviewed'
                                               COMMENT '漏洞状态: unreviewed=未审核, confirmed=已确认, ticketed=已发单, fixed=已修复, false_positive=误报, ignored=忽略',

                                           `asset_domain` VARCHAR(255) DEFAULT NULL COMMENT '漏洞资产Domain',
                                           `asset_host` VARCHAR(255) DEFAULT NULL COMMENT '漏洞资产Host/IP',
                                           `asset_port` INT UNSIGNED DEFAULT NULL COMMENT '漏洞存在端口',

                                           `tags` JSON DEFAULT NULL COMMENT '漏洞标签，JSON数组',
                                           `severity` VARCHAR(16) NOT NULL DEFAULT 'unknown'
                                               COMMENT '漏洞等级: critical/high/medium/low/info/unknown',

                                           `description` TEXT DEFAULT NULL COMMENT '漏洞说明',
                                           `impact` TEXT DEFAULT NULL COMMENT '漏洞影响范围',
                                           `cvss_score` DECIMAL(3,1) DEFAULT NULL COMMENT '漏洞CVSS评分，范围0.0-10.0',

                                           `protocol` VARCHAR(32) DEFAULT NULL COMMENT '漏洞协议，例如 http/tcp/dns/ssl/headless',
                                           `vendor` VARCHAR(128) DEFAULT NULL COMMENT '漏洞厂商',
                                           `product` VARCHAR(128) DEFAULT NULL COMMENT '漏洞产品',

                                           `remediation` TEXT DEFAULT NULL COMMENT '漏洞修复建议',
                                           `reference_links` JSON DEFAULT NULL COMMENT '漏洞参考链接，JSON数组',

                                           `detail` JSON DEFAULT NULL COMMENT '漏洞细节，说明命中原因、探测请求、响应证据、匹配器结果等',

                                           `vuln_fingerprint` CHAR(64) NOT NULL COMMENT '漏洞去重指纹，建议由 template_id + asset_host + asset_port + protocol + 关键路径 计算SHA256',



                                           PRIMARY KEY (`id`),
                                           UNIQUE KEY `uk_vuln_fingerprint` (`vuln_fingerprint`),
                                           KEY `idx_template_id` (`template_id`),
                                           KEY `idx_latest_scan_task_id` (`latest_scan_task_id`),
                                           KEY `idx_status` (`status`),
                                           KEY `idx_severity` (`severity`),
                                           KEY `idx_asset_host_port` (`asset_host`, `asset_port`),
                                           KEY `idx_first_found_at` (`first_found_at`),
                                           KEY `idx_last_found_at` (`last_found_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ManScan扫描漏洞信息表';