package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"unicode"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/secretbox"
	"ManScan/server/internal/repository"

	"gorm.io/gorm"
)

type ThirdPartyAPIKeyService interface {
	Create(ctx context.Context, request dto.CreateThirdPartyAPIKeyRequest) (*dto.ThirdPartyAPIKeyListItem, error)
	List(ctx context.Context, query dto.ListThirdPartyAPIKeysQuery) (*dto.PageResult[dto.ThirdPartyAPIKeyListItem], error)
	Get(ctx context.Context, itemID int64) (*dto.ThirdPartyAPIKeyListItem, error)
	GetPlaintext(ctx context.Context, itemID int64) (*dto.ThirdPartyAPIKeyPlaintextResponse, error)
	Update(ctx context.Context, itemID int64, request dto.UpdateThirdPartyAPIKeyRequest) (*dto.ThirdPartyAPIKeyListItem, error)
	Delete(ctx context.Context, itemID int64) (*dto.DeleteThirdPartyAPIKeyResponse, error)
}

type thirdPartyAPIKeyService struct {
	repository repository.ThirdPartyAPIKeyRepository
	box        *secretbox.Box
}

// NewThirdPartyAPIKeyService 组装配置存储及加密依赖。
func NewThirdPartyAPIKeyService(repo repository.ThirdPartyAPIKeyRepository, box *secretbox.Box) ThirdPartyAPIKeyService {
	return &thirdPartyAPIKeyService{repository: repo, box: box}
}

var ErrInvalidThirdPartyAPIKey = errors.New("第三方 API Key 参数不合法")
var ErrAPIKeyEncryptionUnavailable = errors.New("第三方 API Key 加密器未配置")
var ErrThirdPartyAPIKeyNotConfigured = errors.New("第三方 API Key 未配置")

// Create 加密密钥并创建第三方平台配置。
func (s *thirdPartyAPIKeyService) Create(ctx context.Context, request dto.CreateThirdPartyAPIKeyRequest) (*dto.ThirdPartyAPIKeyListItem, error) {
	key := request.Key
	platformURL := strings.TrimSpace(request.PlatformURL)
	if !validThirdPartyAPIKey(key) || !validThirdPartyAPIKeyInput(platformURL, request.Description) {
		return nil, ErrInvalidThirdPartyAPIKey
	}
	if s.box == nil {
		return nil, ErrAPIKeyEncryptionUnavailable
	}
	ciphertext, err := s.box.Encrypt(key)
	if err != nil {
		return nil, err
	}
	item := &entity.ThirdPartyAPIKey{EncryptedKey: ciphertext, PlatformURL: platformURL, RateLimitPerMinute: request.RateLimitPerMinute, Description: strings.TrimSpace(request.Description)}
	if err := s.repository.Create(ctx, item); err != nil {
		return nil, err
	}
	result := toThirdPartyAPIKeyListItem(*item)
	return &result, nil
}

// List 分页返回第三方平台的非敏感配置。
func (s *thirdPartyAPIKeyService) List(ctx context.Context, query dto.ListThirdPartyAPIKeysQuery) (*dto.PageResult[dto.ThirdPartyAPIKeyListItem], error) {
	page, err := s.repository.List(ctx, query)
	if err != nil {
		return nil, err
	}
	items := make([]dto.ThirdPartyAPIKeyListItem, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, toThirdPartyAPIKeyListItem(item))
	}
	return &dto.PageResult[dto.ThirdPartyAPIKeyListItem]{Page: page.Page, PageSize: page.PageSize, Total: page.Total, TotalPages: page.TotalPages, Items: items}, nil
}

// Update 更新配置；省略 key 时保留现有密钥。
func (s *thirdPartyAPIKeyService) Update(ctx context.Context, itemID int64, request dto.UpdateThirdPartyAPIKeyRequest) (*dto.ThirdPartyAPIKeyListItem, error) {
	if itemID <= 0 {
		return nil, ErrInvalidThirdPartyAPIKey
	}
	if s.box == nil {
		return nil, ErrAPIKeyEncryptionUnavailable
	}
	item, err := s.repository.FindByID(ctx, itemID)
	if err != nil {
		return nil, err
	}
	platformURL := strings.TrimSpace(request.PlatformURL)
	if !validThirdPartyAPIKeyInput(platformURL, request.Description) {
		return nil, ErrInvalidThirdPartyAPIKey
	}
	item.PlatformURL = platformURL
	item.RateLimitPerMinute = request.RateLimitPerMinute
	item.Description = strings.TrimSpace(request.Description)
	if request.Key != nil {
		key := *request.Key
		if !validThirdPartyAPIKey(key) {
			return nil, ErrInvalidThirdPartyAPIKey
		}
		item.EncryptedKey, err = s.box.Encrypt(key)
		if err != nil {
			return nil, err
		}
	}
	if err := s.repository.Update(ctx, item, request.Key != nil); err != nil {
		return nil, err
	}
	return s.Get(ctx, itemID)
}

// Delete 删除指定第三方平台配置。
func (s *thirdPartyAPIKeyService) Delete(ctx context.Context, itemID int64) (*dto.DeleteThirdPartyAPIKeyResponse, error) {
	if itemID <= 0 {
		return nil, ErrInvalidThirdPartyAPIKey
	}
	deleted, err := s.repository.Delete(ctx, itemID)
	if err != nil {
		return nil, err
	}
	if deleted == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &dto.DeleteThirdPartyAPIKeyResponse{ID: itemID, DeletedCount: deleted}, nil
}

func validThirdPartyAPIKeyInput(platformURL, description string) bool {
	if platformURL == "" || len(platformURL) > 2048 || len(description) > 512 {
		return false
	}
	parsed, err := url.ParseRequestURI(platformURL)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != "" && parsed.User == nil && parsed.Fragment == ""
}

func validThirdPartyAPIKey(key string) bool {
	return strings.TrimSpace(key) != "" && len(key) <= 512 && strings.IndexFunc(key, unicode.IsControl) < 0
}

// Get 返回单条配置的非敏感元信息。
func (s *thirdPartyAPIKeyService) Get(ctx context.Context, itemID int64) (*dto.ThirdPartyAPIKeyListItem, error) {
	if itemID <= 0 {
		return nil, ErrInvalidThirdPartyAPIKey
	}
	item, err := s.repository.FindByID(ctx, itemID)
	if err != nil {
		return nil, err
	}
	result := toThirdPartyAPIKeyListItem(*item)
	return &result, nil
}

// GetPlaintext 解密并返回指定第三方 API Key；调用方必须已完成管理员鉴权。
func (s *thirdPartyAPIKeyService) GetPlaintext(ctx context.Context, itemID int64) (*dto.ThirdPartyAPIKeyPlaintextResponse, error) {
	if itemID <= 0 {
		return nil, ErrInvalidThirdPartyAPIKey
	}
	if s.box == nil {
		return nil, ErrAPIKeyEncryptionUnavailable
	}
	item, err := s.repository.FindByID(ctx, itemID)
	if err != nil {
		return nil, err
	}
	if item.EncryptedKey == "" {
		return nil, ErrThirdPartyAPIKeyNotConfigured
	}
	plaintext, err := s.box.Decrypt(item.EncryptedKey)
	if err != nil {
		return nil, err
	}
	return &dto.ThirdPartyAPIKeyPlaintextResponse{Key: plaintext}, nil
}

func toThirdPartyAPIKeyListItem(item entity.ThirdPartyAPIKey) dto.ThirdPartyAPIKeyListItem {
	return dto.ThirdPartyAPIKeyListItem{ID: item.ID, PlatformURL: item.PlatformURL, RateLimitPerMinute: item.RateLimitPerMinute, Description: item.Description, KeyConfigured: item.EncryptedKey != "", CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}
