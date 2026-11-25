// Command notification provisions a Feishu notification without starting scan workers.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"ManScan/server/config"
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func main() {
	name := flag.String("name", "扫描发起通知", "通知名称")
	style := flag.String("style", "orange", "标题栏颜色：blue、orange、purple、red、green、yellow、grey（兼容旧 cat_* 样式）")
	enabled := flag.Bool("enabled", true, "是否开启自动通知")
	flag.Parse()
	logger := logx.New()
	if err := provision(*name, *style, *enabled, logger); err != nil {
		// All errors returned here are fixed messages without credentials.
		logger.Error("notification provisioning failed", "reason", err.Error())
		os.Exit(1)
	}
}

func provision(name, style string, enabled bool, logger *logx.Logger) error {
	webhook := strings.TrimSpace(os.Getenv("MANSCAN_FEISHU_WEBHOOK"))
	if webhook == "" {
		return fmt.Errorf("请设置 MANSCAN_FEISHU_WEBHOOK 环境变量")
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("读取服务配置失败，请检查配置文件及加密密钥")
	}
	db, err := gorm.Open(mysql.Open(cfg.MySQL.DSN()), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		return fmt.Errorf("连接数据库失败")
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("获取数据库连接失败")
	}
	sqlDB.SetMaxOpenConns(1)
	defer func() {
		if err := sqlDB.Close(); err != nil {
			logger.Error("notification database close failed")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo := repository.NewNotificationRepository(db)
	if err = repo.Migrate(ctx); err != nil {
		return fmt.Errorf("初始化通知表失败")
	}
	svc := service.NewNotificationService(repo, nil, nil, logger)
	// Avoid silently creating repeated subscriptions when the command is rerun.
	for page := 1; ; page++ {
		existing, err := svc.List(ctx, page, 100)
		if err != nil {
			return fmt.Errorf("读取已有通知配置失败")
		}
		for _, item := range existing.Items {
			if item.Name == strings.TrimSpace(name) {
				return fmt.Errorf("同名通知已存在，请通过通知 API 修改，避免重复推送")
			}
		}
		if page >= existing.TotalPages {
			break
		}
	}
	created, err := svc.Create(ctx, dto.SaveNotificationRequest{Name: name, Enabled: &enabled, Style: style, Webhook: &webhook})
	if err != nil {

		return fmt.Errorf("创建通知失败，请检查名称、样式及飞书地址")
	}
	stored, err := svc.Get(ctx, created.ID)
	if err != nil || stored.Enabled != enabled || stored.Style != created.Style {
		return fmt.Errorf("通知已创建但回读验证失败，请检查通知列表")
	}
	logger.Info("notification provisioned", "id", stored.ID, "name", stored.Name, "enabled", stored.Enabled, "style", stored.Style)
	return nil
}
