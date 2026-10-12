package dto

type ThemeSettingResponse struct {
	Theme           string `json:"theme"`
	DarkModeEnabled bool   `json:"dark_mode_enabled"`
}

type UpdateThemeSettingRequest struct {
	Theme           string `json:"theme" binding:"required"`
	DarkModeEnabled *bool  `json:"dark_mode_enabled" binding:"required"`
}
