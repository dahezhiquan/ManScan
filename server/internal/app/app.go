package app

import (
	"fmt"
	"net/http"

	"ManScan/server/config"
	"ManScan/server/internal/api"
	"ManScan/server/internal/handler"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func Run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := logx.New()

	db, err := gorm.Open(mysql.Open(cfg.MySQL.DSN()), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("连接数据库失败: %w", err)
	}

	templateRepository := repository.NewTemplateRepository(cfg.TemplateDir)
	templateService := service.NewTemplateService(templateRepository)

	scanTaskRepository := repository.NewScanTaskRepository(db)
	scanTaskService := service.NewScanTaskService(
		scanTaskRepository,
		logger,
		cfg.RootDir,
	)

	router := api.NewRouter(
		logger,
		handler.NewTemplateHandler(templateService),
		handler.NewScanTaskHandler(scanTaskService),
	)

	server := &http.Server{
		Addr:    cfg.Address,
		Handler: router,
	}

	logger.Info("server started", "addr", cfg.Address, "template_dir", cfg.TemplateDir)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("启动 HTTP 服务失败: %w", err)
	}

	return nil
}
