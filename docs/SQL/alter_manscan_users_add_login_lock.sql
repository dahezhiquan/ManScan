ALTER TABLE `manscan_users`
    MODIFY COLUMN `status` ENUM('enabled', 'disabled', 'locked') NOT NULL DEFAULT 'enabled' COMMENT '状态: enabled=启用, disabled=禁用, locked=锁定',
    ADD COLUMN `failed_login_attempts` INT NOT NULL DEFAULT 0 COMMENT '连续登录失败次数' AFTER `status`;
