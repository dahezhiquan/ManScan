package service

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"

	"gorm.io/gorm"
)

type SettingService interface {
	GetTheme(ctx context.Context, userID int64) (*dto.ThemeSettingResponse, error)
	UpdateTheme(ctx context.Context, userID int64, request dto.UpdateThemeSettingRequest) (*dto.ThemeSettingResponse, error)
}

type settingService struct {
	repository repository.UserSettingRepository
}

func NewSettingService(repo repository.UserSettingRepository) SettingService {
	return &settingService{repository: repo}
}

var ErrInvalidThemeSetting = errors.New("主题设置参数不合法")

const defaultTheme = "cartoon"

var themePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func (s *settingService) GetTheme(ctx context.Context, userID int64) (*dto.ThemeSettingResponse, error) {
	if userID <= 0 {
		return nil, ErrInvalidThemeSetting
	}

	setting, err := s.repository.FindByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return defaultThemeSetting(), nil
		}
		return nil, err
	}
	return toThemeSettingResponse(setting), nil
}

func (s *settingService) UpdateTheme(ctx context.Context, userID int64, request dto.UpdateThemeSettingRequest) (*dto.ThemeSettingResponse, error) {
	theme := strings.ToLower(strings.TrimSpace(request.Theme))
	if userID <= 0 || !themePattern.MatchString(theme) || request.DarkModeEnabled == nil {
		return nil, ErrInvalidThemeSetting
	}

	setting := &entity.UserSetting{
		UserID:          userID,
		Theme:           theme,
		DarkModeEnabled: *request.DarkModeEnabled,
	}
	if err := s.repository.UpsertTheme(ctx, setting); err != nil {
		return nil, err
	}
	return toThemeSettingResponse(setting), nil
}

func defaultThemeSetting() *dto.ThemeSettingResponse {
	return &dto.ThemeSettingResponse{
		Theme:           defaultTheme,
		DarkModeEnabled: false,
	}
}

func toThemeSettingResponse(setting *entity.UserSetting) *dto.ThemeSettingResponse {
	if setting == nil {
		return defaultThemeSetting()
	}
	theme := strings.ToLower(strings.TrimSpace(setting.Theme))
	if !themePattern.MatchString(theme) {
		theme = defaultTheme
	}
	return &dto.ThemeSettingResponse{
		Theme:           theme,
		DarkModeEnabled: setting.DarkModeEnabled,
	}
}
