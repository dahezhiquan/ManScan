CREATE TABLE `manscan_doc_documents` (
                                         `id` CHAR(26) NOT NULL COMMENT '漏洞文章随机ID',
                                         `doc_type` ENUM('system_guide','vulnerability_doc') NOT NULL COMMENT '文档类型',
                                         `title` VARCHAR(200) NOT NULL COMMENT '文档标题',
                                         `summary` VARCHAR(500) NOT NULL DEFAULT '' COMMENT '摘要',
                                         `content_md` LONGTEXT NOT NULL COMMENT 'Markdown内容',
                                         `view_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '浏览次数',
                                         `created_by` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '创建人',
                                         `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
                                         `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
                                         PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ManScan文章表';