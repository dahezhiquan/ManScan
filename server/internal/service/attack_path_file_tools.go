package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"sync"
)

const attackPathToolDefaultLines = 1000
const attackPathToolMaxLines = 2000
const attackPathToolMaxBytes = 96000

// attackPathFileTools exposes only the open input/output files of one task attempt.
// No model-provided path, command, or replacement text is accepted.
type attackPathFileTools struct {
	prompts                attackPathPrompts
	mu                     sync.Mutex
	ctx                    context.Context
	key                    string
	scanner                *bufio.Scanner
	output                 *os.File
	writer                 *bufio.Writer
	onProgress             func(context.Context, int, int) error
	total, processed, kept int
	pending                []string
	batchID, carry         string
	eof, finished          bool
	fatal                  error
	lastBatchID            string
	lastRemoved            []int
}

func newAttackPathFileTools(ctx context.Context, key string, input io.Reader, output *os.File, total int, progress func(context.Context, int, int) error, prompts attackPathPrompts) *attackPathFileTools {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 4096)
	return &attackPathFileTools{prompts: prompts, ctx: ctx, key: key, scanner: scanner, output: output, writer: bufio.NewWriter(output), total: total, onProgress: progress}
}

func (t *attackPathFileTools) snapshot() (int, int, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.processed, t.kept, t.finished, t.fatal
}

func (t *attackPathFileTools) readPaths(limit int) (interface{}, error) {
	if limit < 1 || limit > attackPathToolMaxLines {
		return nil, errors.New("limit must be between 1 and 2000")
	}
	if len(t.pending) == 0 && !t.finished {
		size := 0
		for len(t.pending) < limit {
			path := t.carry
			t.carry = ""
			if path == "" {
				if !t.scanner.Scan() {
					t.eof = true
					break
				}
				path = t.scanner.Text()
			}
			if path == "" {
				continue
			}
			if len(path) > 2048 {
				t.fatal = errors.New("invalid input path")
				return nil, t.fatal
			}
			if len(t.pending) > 0 && size+len(path) > attackPathToolMaxBytes {
				t.carry = path
				break
			}
			t.pending = append(t.pending, path)
			size += len(path)
		}
		if err := t.scanner.Err(); err != nil {
			t.fatal = err
			return nil, errors.New("input read failed")
		}
		if t.processed+len(t.pending) > t.total || (t.eof && t.processed+len(t.pending) != t.total) {
			t.fatal = errors.New("input count changed")
			return nil, t.fatal
		}
		if len(t.pending) > 0 {
			id, err := randomAttackPathID()
			if err != nil {
				t.fatal = err
				return nil, err
			}
			t.batchID = id
		}
	}
	return map[string]interface{}{"batch_id": t.batchID, "paths": t.pending, "eof": t.eof && len(t.pending) == 0, "processed": t.processed, "kept": t.kept, "total": t.total, "finished": t.finished}, nil
}

func (t *attackPathFileTools) writeFiltered(batchID string, removed []int) (interface{}, error) {
	if removed == nil {
		return nil, errors.New("malicious_indexes is required; use [] when all paths are normal")
	}
	sort.Ints(removed)
	for i, index := range removed {
		if index < 0 || (i > 0 && removed[i-1] == index) {
			return nil, errors.New("invalid or duplicate index")
		}
	}
	if batchID != "" && batchID == t.lastBatchID {
		if !reflect.DeepEqual(removed, t.lastRemoved) {
			return nil, errors.New("committed batch cannot be changed")
		}
		return t.progress(), nil
	}
	if t.finished || len(t.pending) == 0 || batchID != t.batchID {
		return nil, errors.New("read_paths must return this batch_id before writing")
	}
	for _, index := range removed {
		if index >= len(t.pending) {
			return nil, errors.New("index outside current batch")
		}
	}
	cursor, kept := 0, t.kept
	for i, path := range t.pending {
		if cursor < len(removed) && removed[cursor] == i {
			cursor++
			continue
		}
		if _, err := t.writer.WriteString(path + "\n"); err != nil {
			t.fatal = err
			return nil, errors.New("output write failed")
		}
		kept++
	}
	if err := t.writer.Flush(); err != nil {
		t.fatal = err
		return nil, errors.New("output flush failed")
	}
	processed := t.processed + len(t.pending)
	if t.onProgress != nil {
		if err := t.onProgress(t.ctx, processed, kept); err != nil {
			t.fatal = err
			return nil, errors.New("task lease or progress update failed")
		}
	}
	t.processed, t.kept = processed, kept
	t.lastBatchID, t.lastRemoved = batchID, append([]int{}, removed...)
	t.pending = nil
	t.batchID = ""
	return t.progress(), nil
}

func (t *attackPathFileTools) progress() map[string]interface{} {
	return map[string]interface{}{"processed": t.processed, "kept": t.kept, "total": t.total, "finished": t.finished}
}

func (t *attackPathFileTools) finish() (interface{}, error) {
	if t.finished {
		return t.progress(), nil
	}
	if len(t.pending) > 0 || t.carry != "" || t.processed != t.total {
		return nil, errors.New("all input paths must be read and classified before finish")
	}
	if !t.eof {
		if t.scanner.Scan() {
			t.fatal = errors.New("unprocessed input remains")
			return nil, t.fatal
		}
		if err := t.scanner.Err(); err != nil {
			t.fatal = err
			return nil, errors.New("input read failed")
		}
		t.eof = true
	}
	if err := t.output.Sync(); err != nil {
		t.fatal = err
		return nil, errors.New("output sync failed")
	}
	t.finished = true
	return t.progress(), nil
}

func decodeAttackPathToolArgs(raw json.RawMessage, value interface{}) error {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func (t *attackPathFileTools) call(name string, args json.RawMessage) (interface{}, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	if t.fatal != nil {
		return nil, errors.New("task IO or lease failed; stop this task")
	}
	switch name {
	case "read_paths":
		params := struct {
			Limit int `json:"limit"`
		}{Limit: attackPathToolDefaultLines}
		if err := decodeAttackPathToolArgs(args, &params); err != nil {
			return nil, errors.New("invalid read_paths arguments")
		}
		return t.readPaths(params.Limit)
	case "write_filtered_paths":
		var params struct {
			BatchID string `json:"batch_id"`
			Removed []int  `json:"malicious_indexes"`
		}
		if err := decodeAttackPathToolArgs(args, &params); err != nil {
			return nil, errors.New("invalid write_filtered_paths arguments")
		}
		return t.writeFiltered(params.BatchID, params.Removed)
	case "finish":
		if err := decodeAttackPathToolArgs(args, &struct{}{}); err != nil {
			return nil, errors.New("finish accepts no arguments")
		}
		return t.finish()
	default:
		return nil, errors.New("unknown tool")
	}
}

func attackPathMCPTools(prompts attackPathPrompts) []map[string]interface{} {
	schema := func(properties map[string]interface{}, required []string) map[string]interface{} {
		return map[string]interface{}{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
	}
	return []map[string]interface{}{
		{"name": "read_paths", "description": prompts.readPaths, "inputSchema": schema(map[string]interface{}{"limit": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": attackPathToolMaxLines}}, []string{})},
		{"name": "write_filtered_paths", "description": prompts.writeFilteredPaths, "inputSchema": schema(map[string]interface{}{"batch_id": map[string]string{"type": "string"}, "malicious_indexes": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "integer", "minimum": 0}, "uniqueItems": true}}, []string{"batch_id", "malicious_indexes"})},
		{"name": "finish", "description": prompts.finish, "inputSchema": schema(map[string]interface{}{}, []string{})},
	}
}

// ServeHTTP implements the stateless JSON response variant of MCP Streamable HTTP.
func (t *attackPathFileTools) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+t.key)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Origin") != "" {
		http.Error(w, "origin forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var rpc struct {
		Version string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&rpc); err != nil || rpc.Version != "2.0" {
		http.Error(w, "invalid JSON-RPC", http.StatusBadRequest)
		return
	}
	if len(rpc.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result interface{}
	switch rpc.Method {
	case "initialize":
		result = map[string]interface{}{"protocolVersion": "2025-03-26", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}}, "serverInfo": map[string]string{"name": "manscan-task-files", "version": "1.0.0"}}
	case "ping":
		result = map[string]interface{}{}
	case "tools/list":
		result = map[string]interface{}{"tools": attackPathMCPTools(t.prompts)}
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		var value interface{}
		var err error
		if json.Unmarshal(rpc.Params, &params) != nil {
			err = errors.New("invalid tool parameters")
		} else {
			value, err = t.call(params.Name, params.Arguments)
		}
		var text string
		if err != nil {
			text = err.Error()
		} else {
			encoded, encodeErr := json.Marshal(value)
			if encodeErr != nil {
				err = encodeErr
				text = "tool result encoding failed"
			} else {
				text = string(encoded)
			}
		}
		result = map[string]interface{}{"content": []map[string]string{{"type": "text", "text": text}}, "isError": err != nil}
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": rpc.ID, "error": map[string]interface{}{"code": -32601, "message": "method not found"}})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": rpc.ID, "result": result})
}
