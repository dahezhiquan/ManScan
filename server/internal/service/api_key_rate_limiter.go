package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"ManScan/server/internal/model/dto"
)

// APIKeyRateLimitSource 提供 API Key 的非敏感元数据。
type APIKeyRateLimitSource interface {
	Get(ctx context.Context, itemID int64) (*dto.ThirdPartyAPIKeyListItem, error)
}

// APIKeyRateLimiter 按 API Key ID 统一限制所有任务的外部请求。
type APIKeyRateLimiter interface {
	Wait(ctx context.Context, apiKeyID int64) error
}

type apiKeyRateLimiter struct {
	apiKeys      APIKeyRateLimitSource
	mu           sync.Mutex
	lastRequests map[int64]time.Time
}

// NewAPIKeyRateLimiter 创建供所有定时任务共享的进程内限流器。
func NewAPIKeyRateLimiter(apiKeys APIKeyRateLimitSource) APIKeyRateLimiter {
	return &apiKeyRateLimiter{apiKeys: apiKeys, lastRequests: make(map[int64]time.Time)}
}

// Wait 等待请求额度，等待期间响应取消；每次检查均读取当前限流配置。
func (l *apiKeyRateLimiter) Wait(ctx context.Context, apiKeyID int64) error {
	if apiKeyID <= 0 {
		return ErrInvalidThirdPartyAPIKey
	}
	if l.apiKeys == nil {
		return errors.New("API Key 限流服务不可用")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		item, err := l.apiKeys.Get(ctx, apiKeyID)
		if err != nil {
			return fmt.Errorf("读取 API Key 限流配置失败: %w", err)
		}
		if item == nil {
			return errors.New("API Key 限流配置为空")
		}
		if item.RateLimitPerMinute == 0 {
			return ctx.Err()
		}

		// 向上取整，避免高频配置下纳秒舍入造成实际请求数超出上限。
		limit := time.Duration(item.RateLimitPerMinute)
		interval := (time.Minute + limit - 1) / limit
		l.mu.Lock()
		if err := ctx.Err(); err != nil {
			l.mu.Unlock()
			return err
		}
		now := time.Now()
		allowedAt := l.lastRequests[apiKeyID].Add(interval)
		if !now.Before(allowedAt) {
			// 检查与记账必须原子完成，且按实际放行时间计数。
			l.lastRequests[apiKeyID] = now
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()

		timer := time.NewTimer(time.Until(allowedAt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			// 唤醒后重新竞争额度，避免延迟唤醒的并发任务集中放行。
		}
	}
}
