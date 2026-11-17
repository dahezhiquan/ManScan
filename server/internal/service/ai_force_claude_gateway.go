package service

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ManScan/server/internal/pkg/secretbox"
	"ManScan/server/internal/repository"
)

const aiForceHost = "ai-force.duxiaoman-int.com"

// AIForceClaudeGateway translates Messages text and tool calls into AI Force chat completions.
type AIForceClaudeGateway struct {
	upstream *url.URL
	model    string
	uuapID   string
	localKey string
	repo     repository.ThirdPartyAPIKeyRepository
	box      *secretbox.Box
	client   *http.Client
	limiter  APIKeyRateLimiter
}

func NewAIForceClaudeGateway(baseURL, model, uuapID, localKey string, repo repository.ThirdPartyAPIKeyRepository, box *secretbox.Box) (*AIForceClaudeGateway, error) {
	upstream, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || upstream.Scheme != "https" || upstream.Host != aiForceHost || upstream.Path != "/agent-api/openai" || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" || strings.TrimSpace(model) == "" || strings.TrimSpace(uuapID) == "" || strings.ContainsAny(uuapID, "\r\n") || localKey == "" || repo == nil || box == nil {
		return nil, errors.New("AI Force 配置不合法")
	}
	return &AIForceClaudeGateway{upstream: upstream, model: strings.TrimSpace(model), uuapID: uuapID, localKey: localKey, repo: repo, box: box, client: &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (g *AIForceClaudeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" {
		http.NotFound(w, r)
		return
	}
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if key == "" {
		key = r.Header.Get("x-api-key")
	}
	if subtle.ConstantTimeCompare([]byte(key), []byte(g.localKey)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input claudeGatewayRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&input); err != nil || input.MaxTokens <= 0 || len(input.Messages) == 0 {
		http.Error(w, "unsupported Messages request", http.StatusBadRequest)
		return
	}
	payloadObject, err := gatewayPayload(input, g.model)
	if err != nil {
		http.Error(w, "unsupported Messages content or tools", http.StatusBadRequest)
		return
	}
	completion, err := g.complete(r.Context(), payloadObject)
	if err != nil {
		http.Error(w, "AI Force request failed", http.StatusBadGateway)
		return
	}
	content, stop, err := gatewayResponse(completion, input.Tools)
	if err != nil {
		http.Error(w, "AI Force returned invalid content or tool calls", http.StatusBadGateway)
		return
	}
	if completion.ID == "" {
		completion.ID = "msg_" + newGatewayRequestID()
	}
	message := map[string]interface{}{"id": completion.ID, "type": "message", "role": "assistant", "model": g.model, "content": content, "stop_reason": stop, "stop_sequence": nil, "usage": map[string]int{"input_tokens": completion.Usage.Prompt, "output_tokens": completion.Usage.Completion}}
	if input.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		start := map[string]interface{}{"id": completion.ID, "type": "message", "role": "assistant", "model": g.model, "content": []interface{}{}, "stop_reason": nil, "stop_sequence": nil, "usage": map[string]int{"input_tokens": completion.Usage.Prompt, "output_tokens": 0}}
		writeClaudeEvent(w, "message_start", map[string]interface{}{"type": "message_start", "message": start})
		for index, block := range content {
			initial := map[string]interface{}{"type": block["type"]}
			delta := map[string]interface{}{}
			if block["type"] == "text" {
				initial["text"] = ""
				delta["type"] = "text_delta"
				delta["text"] = block["text"]
			} else {
				initial["id"] = block["id"]
				initial["name"] = block["name"]
				initial["input"] = map[string]interface{}{}
				delta["type"] = "input_json_delta"
				delta["partial_json"] = string(block["input"].(json.RawMessage))
			}
			writeClaudeEvent(w, "content_block_start", map[string]interface{}{"type": "content_block_start", "index": index, "content_block": initial})
			writeClaudeEvent(w, "content_block_delta", map[string]interface{}{"type": "content_block_delta", "index": index, "delta": delta})
			writeClaudeEvent(w, "content_block_stop", map[string]interface{}{"type": "content_block_stop", "index": index})
		}
		writeClaudeEvent(w, "message_delta", map[string]interface{}{"type": "message_delta", "delta": map[string]interface{}{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]int{"output_tokens": completion.Usage.Completion}})
		writeClaudeEvent(w, "message_stop", map[string]string{"type": "message_stop"})
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(message)
}

func flattenClaudeText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, nil
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return "", err
	}
	parts := make([]string, 0, len(blocks))
	for _, block := range blocks {
		if block.Type != "text" {
			return "", errors.New("non-text content is unsupported")
		}
		parts = append(parts, block.Text)
	}
	return strings.Join(parts, "\n"), nil
}

func writeClaudeEvent(w http.ResponseWriter, name string, data interface{}) {
	encoded, err := json.Marshal(data)
	if err == nil {
		_, _ = io.WriteString(w, "event: "+name+"\ndata: "+string(encoded)+"\n\n")
	}
}

func newGatewayRequestID() string {
	id, err := randomAttackPathID()
	if err != nil {
		return time.Now().UTC().Format("20060102150405")
	}
	return id
}

var _ http.Handler = (*AIForceClaudeGateway)(nil)
