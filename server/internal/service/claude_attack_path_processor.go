package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type claudeAttackPathProcessor struct {
	binary, model, promptFile string
	env                       []string
}

// NewClaudeAttackPathProcessor runs one tool-enabled Claude CLI session for an entire file.
func NewClaudeAttackPathProcessor(binary, baseURL, apiKey, model, promptFile string) (AttackPathFileProcessor, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed == nil {
		return nil, errors.New("Claude 本地网关配置不合法")
	}
	local := parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "::1")
	if (parsed.Scheme != "https" && !local) || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.TrimSpace(apiKey) == "" || strings.TrimSpace(model) == "" {
		return nil, errors.New("Claude 本地网关配置不合法")
	}
	if strings.TrimSpace(binary) == "" {
		binary = "claude"
	}
	if strings.TrimSpace(promptFile) == "" {
		return nil, errors.New("prompt.yaml 路径不能为空")
	}
	promptFile, err = filepath.Abs(promptFile)
	if err != nil {
		return nil, fmt.Errorf("解析 prompt.yaml 路径失败: %w", err)
	}
	if _, err := loadAttackPathPrompts(promptFile, 1); err != nil {
		return nil, err
	}
	return &claudeAttackPathProcessor{binary: binary, model: strings.TrimSpace(model), promptFile: promptFile, env: []string{
		"ANTHROPIC_BASE_URL=" + strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		"ANTHROPIC_API_KEY=" + strings.TrimSpace(apiKey),
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"ENABLE_TOOL_SEARCH=false",
		"MAX_THINKING_TOKENS=0",
	}}, nil
}

func (c *claudeAttackPathProcessor) Process(ctx context.Context, input io.Reader, output *os.File, total int, progress func(context.Context, int, int) error) (int, int, error) {
	prompts, err := loadAttackPathPrompts(c.promptFile, total)
	if err != nil {
		return 0, 0, fmt.Errorf("加载攻击路径提示词失败: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, 24*time.Hour)
	defer cancel()
	workDir, err := os.MkdirTemp("", "manscan-attack-path-agent-*")
	if err != nil {
		return 0, 0, fmt.Errorf("创建 Claude 工作目录失败: %w", err)
	}
	defer os.RemoveAll(workDir)
	key, err := randomAttackPathID()
	if err != nil {
		return 0, 0, err
	}
	files := newAttackPathFileTools(callCtx, key, input, output, total, progress, prompts)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, 0, err
	}
	server := &http.Server{Handler: files, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, BaseContext: func(net.Listener) context.Context { return callCtx }}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cancel()
		}
	}()
	defer func() { _ = server.Close(); <-serverDone }()
	config := map[string]interface{}{"mcpServers": map[string]interface{}{"manscan": map[string]interface{}{"type": "http", "url": "http://" + listener.Addr().String() + "/mcp", "headers": map[string]string{"Authorization": "Bearer " + key}}}}
	encoded, err := json.Marshal(config)
	if err != nil {
		return 0, 0, err
	}
	configPath := filepath.Join(workDir, "mcp.json")
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		return 0, 0, err
	}
	cmd := exec.CommandContext(callCtx, c.binary, "--bare", "-p", prompts.task,
		"--system-prompt", prompts.system, "--model", c.model,
		"--tools", "", "--allowedTools", "mcp__manscan__read_paths", "mcp__manscan__write_filtered_paths", "mcp__manscan__finish",
		"--permission-mode", "dontAsk", "--strict-mcp-config", "--mcp-config", configPath,
		"--setting-sources", "", "--no-session-persistence", "--disable-slash-commands", "--output-format", "json")
	cmd.Dir = workDir
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + workDir, "CLAUDE_CONFIG_DIR=" + workDir,
		"HTTPS_PROXY=" + os.Getenv("HTTPS_PROXY"), "HTTP_PROXY=" + os.Getenv("HTTP_PROXY"),
		"NO_PROXY=127.0.0.1,localhost,::1," + os.Getenv("NO_PROXY"), "NODE_EXTRA_CA_CERTS=" + os.Getenv("NODE_EXTRA_CA_CERTS")}, c.env...)
	stdout := &limitedAttackPathOutput{limit: 1 << 20}
	cmd.Stdout = stdout
	runErr := cmd.Run()
	// Close outstanding MCP connections before examining final file state.
	cancel()
	_ = server.Close()
	processed, kept, finished, fileErr := files.snapshot()
	if fileErr != nil {
		return processed, kept, fileErr
	}
	if runErr != nil {
		return processed, kept, fmt.Errorf("Claude CLI 文件编排失败: %w", runErr)
	}
	if ctx.Err() != nil {
		return processed, kept, ctx.Err()
	}
	var response struct {
		Type    string `json:"type"`
		IsError bool   `json:"is_error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil || response.Type != "result" || response.IsError {
		return processed, kept, errors.New("Claude CLI 未返回成功结果")
	}
	if !finished || processed != total {
		return processed, kept, errors.New("Claude CLI 未完成全部路径处理或结果文件确认")
	}
	return processed, kept, nil
}

type limitedAttackPathOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (w *limitedAttackPathOutput) Write(data []byte) (int, error) {
	if len(data) > w.limit-w.buffer.Len() {
		return 0, errors.New("Claude CLI 输出超过限制")
	}
	return w.buffer.Write(data)
}
func (w *limitedAttackPathOutput) Bytes() []byte { return w.buffer.Bytes() }
