package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/secretbox"
)

type aiForceKeyRepo struct{ item *entity.ThirdPartyAPIKey }

func (r aiForceKeyRepo) Create(context.Context, *entity.ThirdPartyAPIKey) error { return nil }
func (r aiForceKeyRepo) List(context.Context, dto.ListThirdPartyAPIKeysQuery) (*dto.PageResult[entity.ThirdPartyAPIKey], error) {
	return nil, nil
}
func (r aiForceKeyRepo) FindByID(_ context.Context, id int64) (*entity.ThirdPartyAPIKey, error) {
	return r.item, nil
}
func (r aiForceKeyRepo) FindAIForce(context.Context) (*entity.ThirdPartyAPIKey, error) {
	return r.item, nil
}
func (r aiForceKeyRepo) Update(context.Context, *entity.ThirdPartyAPIKey, bool) error { return nil }
func (r aiForceKeyRepo) Delete(context.Context, int64) (int64, error)                 { return 0, nil }

func TestAIForceClaudeGatewayConvertsMessages(t *testing.T) {
	box, err := secretbox.New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.Encrypt("real-upstream-key")
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewAIForceClaudeGateway("https://ai-force.duxiaoman-int.com/agent-api/openai", "global.anthropic.claude-sonnet-5", "operator_dxm", "local-secret", aiForceKeyRepo{&entity.ThirdPartyAPIKey{PlatformURL: "https://ai-force.duxiaoman-int.com/", EncryptedKey: ciphertext}}, box)
	if err != nil {
		t.Fatal(err)
	}
	gateway.client = &http.Client{Transport: gatewayTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://ai-force.duxiaoman-int.com/agent-api/openai/v1/chat/completions" || req.Header.Get("Authorization") != "Bearer real-upstream-key" || req.Header.Get("UUAP-ID") != "operator_dxm" || req.Header.Get("REQUEST-ID") == "" {
			t.Errorf("upstream route or headers incorrect: url=%s", req.URL)
		}
		var payload struct {
			Model    string              `json:"model"`
			Messages []map[string]string `json:"messages"`
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload.Model != "global.anthropic.claude-sonnet-5" || len(payload.Messages) != 2 || payload.Messages[1]["content"] != "[/api/ok]" {
			t.Errorf("unexpected payload: %#v", payload)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"msg_test","choices":[{"message":{"content":"{\"malicious_indexes\":[]}"}}],"usage":{"prompt_tokens":12,"completion_tokens":8}}`))}, nil
	})}
	for _, stream := range []bool{false, true} {
		body, _ := json.Marshal(map[string]interface{}{"model": "global.anthropic.claude-sonnet-5", "max_tokens": 128, "stream": stream, "system": "Classify paths", "messages": []map[string]interface{}{{"role": "user", "content": []map[string]string{{"type": "text", "text": "[/api/ok]"}}}}})
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
		req.Header.Set("x-api-key", "local-secret")
		rec := httptest.NewRecorder()
		gateway.ServeHTTP(rec, req)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "malicious_indexes") {
			t.Fatalf("stream=%v status=%d body=%s", stream, rec.Code, rec.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	gateway.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", rec.Code)
	}
}

type gatewayTransport func(*http.Request) (*http.Response, error)

func (f gatewayTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
