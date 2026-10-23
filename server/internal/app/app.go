package app

import (
	"fmt"
	"net/http"
	"path/filepath"

	"ManScan/server/config"
	"ManScan/server/internal/api"
	"ManScan/server/internal/handler"
	authpkg "ManScan/server/internal/pkg/auth"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/pkg/secretbox"
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
	vulnerabilityRepository := repository.NewVulnerabilityRepository(db)
	assetDomainRepository := repository.NewAssetDomainRepository(db)
	assetDomainScreenshotRepository := repository.NewAssetDomainScreenshotRepository(filepath.Join(cfg.RootDir, "screenshots"))
	assetHostRepository := repository.NewAssetHostRepository(db)
	assetHostPortRepository := repository.NewAssetHostPortRepository(db)
	assetConfigCenterRepository := repository.NewAssetConfigCenterRepository(db)
	thirdPartyAPIKeyRepository := repository.NewThirdPartyAPIKeyRepository(db)
	userSettingRepository := repository.NewUserSettingRepository(db)
	userRepository := repository.NewUserRepository(db)
	userSessionRepository := repository.NewUserSessionRepository(db)
	authChallengeRepository := repository.NewAuthChallengeRepository(db)
	tokenManager := authpkg.NewJWTManager(cfg.Auth.JWTSecret, "manscan-server")
	vulnerabilityService := service.NewVulnerabilityService(vulnerabilityRepository)
	assetDomainService := service.NewAssetDomainService(assetDomainRepository, assetDomainScreenshotRepository)
	assetHostService := service.NewAssetHostService(assetHostRepository)
	assetConfigCenterService := service.NewAssetConfigCenterService(assetConfigCenterRepository)
	apiKeyBox, err := secretbox.New(cfg.Auth.APIKeyEncryptionKey)
	if err != nil {
		return fmt.Errorf("初始化第三方 API Key 加密器失败: %w", err)
	}
	thirdPartyAPIKeyService := service.NewThirdPartyAPIKeyService(thirdPartyAPIKeyRepository, apiKeyBox)
	settingService := service.NewSettingService(userSettingRepository)
	dashboardRepository := repository.NewDashboardRepository(db)
	dashboardService := service.NewDashboardService(dashboardRepository, logger)
	authService := service.NewAuthService(userRepository, userSessionRepository, authChallengeRepository, tokenManager, cfg.Auth.TokenTTL())
	scanTaskService := service.NewScanTaskService(
		scanTaskRepository,
		vulnerabilityRepository,
		assetDomainRepository,
		assetHostRepository,
		assetHostPortRepository,
		templateRepository,
		logger,
		cfg.RootDir,
	)

	router := api.NewRouter(
		logger,
		handler.NewAuthHandler(authService),
		authService,
		handler.NewTemplateHandler(templateService),
		handler.NewScanTaskHandler(scanTaskService),
		handler.NewVulnerabilityHandler(vulnerabilityService),
		handler.NewAssetDomainHandler(assetDomainService),
		handler.NewAssetHostHandler(assetHostService),
		handler.NewAssetConfigCenterHandler(assetConfigCenterService),
		handler.NewThirdPartyAPIKeyHandler(thirdPartyAPIKeyService, logger),
		handler.NewSettingHandler(settingService),
		handler.NewDashboardHandler(dashboardService),
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
