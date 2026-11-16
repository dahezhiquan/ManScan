package service

import (
	"encoding/json"
	"testing"
)

func TestAIForceClaudeGatewayToolHistoryAndChoice(t *testing.T) {
	var input claudeGatewayRequest
	body := `{"max_tokens":100,"tools":[{"name":"read_paths","input_schema":{"type":"object"}}],"tool_choice":{"type":"tool","name":"read_paths","disable_parallel_tool_use":true},"messages":[{"role":"user","content":"start"},{"role":"assistant","content":[{"type":"text","text":"reading"},{"type":"tool_use","id":"call1","name":"read_paths","input":{"limit":2}},{"type":"tool_use","id":"call2","name":"read_paths","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"call1","content":[{"type":"text","text":"data"}]},{"type":"tool_result","tool_use_id":"call2","content":"retry","is_error":true},{"type":"text","text":"continue"}]}]}`
	if err := json.Unmarshal([]byte(body), &input); err != nil {
		t.Fatal(err)
	}
	payload, err := gatewayPayload(input, "configured-model")
	if err != nil {
		t.Fatal(err)
	}
	messages := payload["messages"].([]map[string]interface{})
	if len(messages) != 5 || messages[2]["role"] != "tool" || messages[2]["tool_call_id"] != "call1" || messages[3]["content"] != "Tool error: retry" || messages[4]["content"] != "continue" {
		t.Fatalf("bad history: %#v", messages)
	}
	if payload["model"] != "configured-model" || payload["parallel_tool_calls"] != false {
		t.Fatal("model or parallel choice lost")
	}
	choice := payload["tool_choice"].(map[string]interface{})
	if choice["type"] != "function" {
		t.Fatal("tool choice not translated")
	}
	input.Messages = input.Messages[:2]
	if _, err := gatewayPayload(input, "configured-model"); err == nil {
		t.Fatal("accepted unresolved tool calls")
	}
}

func TestAIForceClaudeGatewayStopReasonsAndInvalidCalls(t *testing.T) {
	var completion gatewayCompletion
	if err := json.Unmarshal([]byte(`{"choices":[{"message":{"content":"partial"},"finish_reason":"length"}]}`), &completion); err != nil {
		t.Fatal(err)
	}
	_, stop, err := gatewayResponse(completion, nil)
	if err != nil || stop != "max_tokens" {
		t.Fatalf("stop=%s err=%v", stop, err)
	}
	if err := json.Unmarshal([]byte(`{"choices":[{"message":{"content":null,"tool_calls":[{"id":"call1","type":"function","function":{"name":"read_paths","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`), &completion); err != nil {
		t.Fatal(err)
	}
	if _, _, err := gatewayResponse(completion, nil); err == nil {
		t.Fatal("accepted unknown tool")
	}
	blocks, stop, err := gatewayResponse(completion, []claudeGatewayTool{{Name: "read_paths"}})
	if err != nil || stop != "tool_use" || len(blocks) != 1 || blocks[0]["type"] != "tool_use" {
		t.Fatalf("blocks=%v stop=%s err=%v", blocks, stop, err)
	}
	completion.Choices[0].Message.ToolCalls[0].Function.Arguments = "[1,2]"
	if _, _, err := gatewayResponse(completion, []claudeGatewayTool{{Name: "read_paths"}}); err == nil {
		t.Fatal("accepted non-object tool arguments")
	}
}
