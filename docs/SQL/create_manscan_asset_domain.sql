CREATE TABLE `manscan_asset_domain` (
                                        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                        `domain` VARCHAR(255) NOT NULL COMMENT '域名',
                                        `owner` VARCHAR(100) DEFAULT NULL COMMENT '负责人',
                                        `title` VARCHAR(255) DEFAULT NULL COMMENT '站点标题',

                                        `crawler_path_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '爬虫得到的路径数量',
                                        `whitebox_path_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '白盒路径数量',

                                        `first_alive_at` DATETIME DEFAULT NULL COMMENT '第一次扫描存活时间',
                                        `last_alive_at` DATETIME DEFAULT NULL COMMENT '上次扫描存活时间',

                                        `region` VARCHAR(100) DEFAULT NULL COMMENT '区域',
                                        `vulnerability_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '漏洞总数量，不包含info等级',
                                        `critical_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '严重漏洞数量',
                                        `high_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '高危漏洞数量',
                                        `medium_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '中危漏洞数量',
                                        `low_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '低危漏洞数量',

                                        `components` TEXT DEFAULT NULL COMMENT '组件名称列表，多个组件用逗号分隔',
                                        `component_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '组件数量',

                                        `risk_level` VARCHAR(32) DEFAULT NULL COMMENT '风险等级',

                                        `has_form` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否存在表单：0否，1是',
                                        `has_upload` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否存在上传点：0否，1是',
                                        `has_admin` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否存在后台：0否，1是',

                                        `has_uc_login` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否接入UC登录：0否，1是',
                                        `has_baidu_login` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否接入百度登录：0否，1是',

                                        `screenshot_path` VARCHAR(500) DEFAULT NULL COMMENT '网页截图路径',
                                        `manual_note` TEXT DEFAULT NULL COMMENT '人工注释',
                                        `http_status_code` SMALLINT UNSIGNED DEFAULT NULL COMMENT '响应状态码',
                                        `request` LONGTEXT DEFAULT NULL COMMENT '资产探测请求原文',
                                        `response` LONGTEXT DEFAULT NULL COMMENT '资产探测响应原文',
                                        `is_alive` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否存活：0否，1是',

                                        PRIMARY KEY (`id`),
                                        UNIQUE KEY `uk_domain` (`domain`),
                                        KEY `idx_owner` (`owner`),
                                        KEY `idx_region` (`region`),
                                        KEY `idx_risk_level` (`risk_level`),
                                        KEY `idx_is_alive` (`is_alive`),
                                        KEY `idx_last_alive_at` (`last_alive_at`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
    COMMENT='域名资产表';
