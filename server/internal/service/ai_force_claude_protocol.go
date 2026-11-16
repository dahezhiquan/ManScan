package service

import (
	"encoding/json"
	"errors"
	"strings"
)

type claudeGatewayMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type claudeGatewayTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	Type        string          `json:"type,omitempty"`
}

type claudeGatewayRequest struct {
	Model        string                 `json:"model"`
	System       json.RawMessage        `json:"system"`
	Messages     []claudeGatewayMessage `json:"messages"`
	MaxTokens    int                    `json:"max_tokens"`
	Stream       bool                   `json:"stream"`
	Tools        []claudeGatewayTool    `json:"tools"`
	ToolChoice   json.RawMessage        `json:"tool_choice"`
	OutputConfig json.RawMessage        `json:"output_config"`
}

type claudeGatewayBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

type gatewayToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type gatewayCompletion struct {
	ID      string `json:"id"`
	Choices []struct {
		Message struct {
			Content   *string           `json:"content"`
			ToolCalls []gatewayToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		Prompt     int `json:"prompt_tokens"`
		Completion int `json:"completion_tokens"`
	} `json:"usage"`
}

func gatewayPayload(input claudeGatewayRequest, model string) (map[string]interface{}, error) {
	system, err := flattenClaudeText(input.System)
	if err != nil {
		return nil, err
	}
	if len(input.OutputConfig) > 0 && string(input.OutputConfig) != "null" {
		var config struct {
			Format json.RawMessage `json:"format"`
		}
		if err := json.Unmarshal(input.OutputConfig, &config); err != nil {
			return nil, err
		}
		if len(config.Format) > 0 {
			system += "\nReturn valid JSON matching this output format: " + string(config.Format)
		}
	}
	messages := make([]map[string]interface{}, 0, len(input.Messages)+1)
	if system != "" {
		messages = append(messages, map[string]interface{}{"role": "system", "content": system})
	}
	pending := make(map[string]bool)
	for _, item := range input.Messages {
		if item.Role != "user" && item.Role != "assistant" {
			return nil, errors.New("unsupported message role")
		}
		var plain string
		if json.Unmarshal(item.Content, &plain) == nil && string(item.Content) != "null" {
			if len(pending) > 0 {
				return nil, errors.New("missing tool results")
			}
			messages = append(messages, map[string]interface{}{"role": item.Role, "content": plain})
			continue
		}
		if item.Role == "assistant" && len(pending) > 0 {
			return nil, errors.New("missing tool results")
		}
		var blocks []claudeGatewayBlock
		if err := json.Unmarshal(item.Content, &blocks); err != nil || blocks == nil {
			return nil, errors.New("invalid content blocks")
		}
		texts := []string{}
		calls := []gatewayToolCall{}
		for _, block := range blocks {
			switch block.Type {
			case "text":
				texts = append(texts, block.Text)
			case "tool_use":
				if item.Role != "assistant" || block.ID == "" || block.Name == "" || !gatewayJSONObject(block.Input) || pending[block.ID] {
					return nil, errors.New("invalid tool use")
				}
				call := gatewayToolCall{ID: block.ID, Type: "function"}
				call.Function.Name = block.Name
				call.Function.Arguments = string(block.Input)
				calls = append(calls, call)
				pending[block.ID] = true
			case "tool_result":
				if item.Role != "user" || !pending[block.ToolUseID] {
					return nil, errors.New("orphan tool result")
				}
				text, err := flattenClaudeText(block.Content)
				if err != nil {
					return nil, err
				}
				if block.IsError {
					text = "Tool error: " + text
				}
				messages = append(messages, map[string]interface{}{"role": "tool", "tool_call_id": block.ToolUseID, "content": text})
				delete(pending, block.ToolUseID)
			case "thinking", "redacted_thinking":
				if item.Role != "assistant" {
					return nil, errors.New("invalid thinking block")
				}
			default:
				return nil, errors.New("unsupported content block")
			}
		}
		if item.Role == "user" && len(pending) > 0 {
			return nil, errors.New("missing tool results")
		}
		if len(texts) > 0 || len(calls) > 0 {
			message := map[string]interface{}{"role": item.Role, "content": strings.Join(texts, "\n")}
			if len(calls) > 0 {
				message["tool_calls"] = calls
			}
			messages = append(messages, message)
		}
	}
	if len(pending) > 0 {
		return nil, errors.New("missing tool results")
	}
	payload := map[string]interface{}{"model": model, "messages": messages, "max_tokens": input.MaxTokens, "stream": false}
	names := make(map[string]bool)
	tools := make([]map[string]interface{}, 0, len(input.Tools))
	for _, tool := range input.Tools {
		if tool.Name == "" || names[tool.Name] || (tool.Type != "" && tool.Type != "custom") || !gatewayJSONObject(tool.InputSchema) {
			return nil, errors.New("unsupported tool definition")
		}
		names[tool.Name] = true
		tools = append(tools, map[string]interface{}{"type": "function", "function": map[string]interface{}{"name": tool.Name, "description": tool.Description, "parameters": tool.InputSchema}})
	}
	if len(tools) > 0 {
		payload["tools"] = tools
	}
	if len(input.ToolChoice) > 0 && string(input.ToolChoice) != "null" {
		var choice struct {
			Type            string `json:"type"`
			Name            string `json:"name"`
			DisableParallel bool   `json:"disable_parallel_tool_use"`
		}
		if err := json.Unmarshal(input.ToolChoice, &choice); err != nil {
			return nil, err
		}
		switch choice.Type {
		case "auto", "none":
			payload["tool_choice"] = choice.Type
		case "any":
			if len(tools) == 0 {
				return nil, errors.New("tool choice requires tools")
			}
			payload["tool_choice"] = "required"
		case "tool":
			if !names[choice.Name] {
				return nil, errors.New("unknown forced tool")
			}
			payload["tool_choice"] = map[string]interface{}{"type": "function", "function": map[string]string{"name": choice.Name}}
		default:
			return nil, errors.New("unsupported tool choice")
		}
		if choice.DisableParallel {
			payload["parallel_tool_calls"] = false
		}
	}
	return payload, nil
}

func gatewayJSONObject(raw json.RawMessage) bool {
	var value map[string]json.RawMessage
	return json.Unmarshal(raw, &value) == nil && value != nil
}

func gatewayResponse(completion gatewayCompletion, tools []claudeGatewayTool) ([]map[string]interface{}, string, error) {
	if len(completion.Choices) != 1 {
		return nil, "", errors.New("invalid choices")
	}
	choice := completion.Choices[0]
	content := []map[string]interface{}{}
	if choice.Message.Content != nil && *choice.Message.Content != "" {
		content = append(content, map[string]interface{}{"type": "text", "text": *choice.Message.Content})
	}
	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Name] = true
	}
	ids := make(map[string]bool)
	for _, call := range choice.Message.ToolCalls {
		if call.Type != "function" || call.ID == "" || ids[call.ID] || !names[call.Function.Name] || !gatewayJSONObject(json.RawMessage(call.Function.Arguments)) {
			return nil, "", errors.New("invalid upstream tool call")
		}
		ids[call.ID] = true
		content = append(content, map[string]interface{}{"type": "tool_use", "id": call.ID, "name": call.Function.Name, "input": json.RawMessage(call.Function.Arguments)})
	}
	stop := "end_turn"
	switch choice.FinishReason {
	case "length":
		stop = "max_tokens"
	case "tool_calls":
		if len(choice.Message.ToolCalls) == 0 {
			return nil, "", errors.New("missing upstream tool calls")
		}
		stop = "tool_use"
	case "stop", "":
		if len(choice.Message.ToolCalls) > 0 {
			stop = "tool_use"
		}
	default:
		return nil, "", errors.New("unsupported upstream stop reason")
	}
	if len(content) == 0 {
		return nil, "", errors.New("empty completion")
	}
	return content, stop, nil
}
