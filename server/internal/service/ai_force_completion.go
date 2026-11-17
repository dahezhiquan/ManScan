package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type aiForceRequestError struct {
	status     int
	code       int
	retryAfter time.Duration
}

func (e *aiForceRequestError) Error() string {
	return fmt.Sprintf("AI Force request failed (HTTP %d, code %d)", e.status, e.code)
}

// complete shares credential validation and transport between CLI and batch mode.
// Upstream bodies, request payloads and credentials never enter error messages.
func (g *AIForceClaudeGateway) complete(ctx context.Context, payloadObject map[string]interface{}) (gatewayCompletion, error) {
	var completion gatewayCompletion
	payload, err := json.Marshal(payloadObject)
	if err != nil {
		return completion, errors.New("invalid AI Force request")
	}
	item, err := g.repo.FindAIForce(ctx)
	if err != nil || item == nil {
		return completion, errors.New("AI Force key unavailable")
	}
	platform, err := url.Parse(strings.TrimSpace(item.PlatformURL))
	if err != nil || platform.Scheme != "https" || platform.Host != aiForceHost || platform.User != nil || platform.RawQuery != "" || platform.Fragment != "" || (platform.Path != "" && platform.Path != "/" && platform.Path != "/agent-api/openai") {
		return completion, errors.New("AI Force key record does not match platform")
	}
	if g.limiter != nil {
		if err := g.limiter.Wait(ctx, item.ID); err != nil {
			return completion, fmt.Errorf("AI Force rate limit: %w", err)
		}
	}
	secret, err := g.box.Decrypt(item.EncryptedKey)
	if err != nil || strings.TrimSpace(secret) == "" {
		return completion, errors.New("AI Force key unavailable")
	}
	upstreamURL := *g.upstream
	upstreamURL.Path += "/v1/chat/completions"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL.String(), bytes.NewReader(payload))
	if err != nil {
		return completion, errors.New("invalid AI Force request")
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("UUAP-ID", g.uuapID)
	request.Header.Set("REQUEST-ID", newGatewayRequestID())
	request.Header.Set("Content-Type", "application/json")
	response, err := g.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return completion, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return completion, context.DeadlineExceeded
		}
		return completion, &aiForceRequestError{}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return completion, &aiForceRequestError{status: response.StatusCode, retryAfter: aiForceRetryAfter(response.Header.Get("Retry-After"))}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil {
		if ctx.Err() != nil {
			return completion, ctx.Err()
		}
		return completion, &aiForceRequestError{}
	}
	if len(data) > 4<<20 || json.Unmarshal(data, &completion) != nil {
		return completion, errors.New("AI Force returned an invalid response")
	}
	if len(completion.Choices) == 0 {
		var envelope struct {
			Code int `json:"code"`
		}
		if json.Unmarshal(data, &envelope) == nil && envelope.Code != 0 {
			status := http.StatusOK
			// AI Force reports concurrency rejection inside an HTTP 200 body.
			if envelope.Code == 110602 {
				status = http.StatusTooManyRequests
			}
			return completion, &aiForceRequestError{status: status, code: envelope.Code, retryAfter: aiForceRetryAfter(response.Header.Get("Retry-After"))}
		}
	}
	return completion, nil
}

func aiForceRetryAfter(value string) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(min(seconds, 300)) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		return max(0, min(time.Until(date), 5*time.Minute))
	}
	return 0
}
