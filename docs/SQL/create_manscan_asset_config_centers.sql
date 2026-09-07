CREATE TABLE `manscan_asset_config_centers` (
                                               `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
                                               `item_name` VARCHAR(128) NOT NULL COMMENT '项名称',
                                               `big_category` VARCHAR(128) NOT NULL COMMENT '大分类',
                                               `small_category` VARCHAR(128) NOT NULL COMMENT '小分类',
                                               `status` ENUM('enabled', 'disabled') NOT NULL DEFAULT 'enabled' COMMENT '状态: enabled=启用, disabled=未启用',
                                               `description` VARCHAR(500) DEFAULT NULL COMMENT '说明',
                                               PRIMARY KEY (`id`),
                                               UNIQUE KEY `uk_item_name` (`item_name`),
                                               KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ManScan资产配置中心表';
