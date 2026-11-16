package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxPromptFileBytes = 1 << 20
const maxPromptBytes = 32 << 10

// PromptCatalog is one immutable snapshot of the prompts in prompt.yaml.
type PromptCatalog struct {
	prompts map[string]string
}

// PromptFilePath locates prompt.yaml beside the loaded server configuration.
func (c Config) PromptFilePath() string {
	configFile := c.ConfigFile
	if configFile == "" {
		configFile = "config.yaml"
	}
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(c.RootDir, configFile)
	}
	return filepath.Join(filepath.Dir(configFile), "prompt.yaml")
}

// LoadPromptCatalog reads a fresh, validated prompt catalog without caching.
func LoadPromptCatalog(path string) (*PromptCatalog, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("读取 prompt.yaml 失败: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxPromptFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取 prompt.yaml 失败: %w", err)
	}
	if len(data) > maxPromptFileBytes {
		return nil, errors.New("prompt.yaml 不能超过 1 MiB")
	}
	var document struct {
		Prompts map[string]yaml.Node `yaml:"prompts"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("解析 prompt.yaml 失败: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("prompt.yaml 只允许一个 YAML 文档")
	}
	if len(document.Prompts) == 0 {
		return nil, errors.New("prompt.yaml 的 prompts 不能为空")
	}
	catalog := &PromptCatalog{prompts: make(map[string]string, len(document.Prompts))}
	for id, node := range document.Prompts {
		if strings.TrimSpace(id) == "" || strings.TrimSpace(id) != id {
			return nil, errors.New("prompt.yaml 提示词标识不能为空或包含首尾空白")
		}
		if node.Kind != yaml.ScalarNode || node.Tag != "!!str" || strings.TrimSpace(node.Value) == "" || strings.ContainsRune(node.Value, '\x00') || len(node.Value) > maxPromptBytes {
			return nil, fmt.Errorf("提示词 %q 必须是非空字符串，不能含 NUL，且不能超过 32 KiB", id)
		}
		catalog.prompts[id] = strings.TrimSpace(node.Value)
	}
	return catalog, nil
}

// Render looks up an identifier and substitutes literal {{name}} placeholders.
// It never evaluates templates, commands, or values inserted by another variable.
func (c *PromptCatalog) Render(id string, variables map[string]string) (string, error) {
	remaining, ok := c.prompts[id]
	if !ok {
		return "", fmt.Errorf("prompt.yaml 缺少提示词标识 %q", id)
	}
	var output strings.Builder
	for {
		start := strings.Index(remaining, "{{")
		if start < 0 {
			if strings.Contains(remaining, "}}") {
				return "", fmt.Errorf("提示词 %q 的占位符括号不匹配", id)
			}
			output.WriteString(remaining)
			break
		}
		end := strings.Index(remaining[start+2:], "}}")
		if end < 0 || strings.Contains(remaining[:start], "}}") {
			return "", fmt.Errorf("提示词 %q 的占位符括号不匹配", id)
		}
		end += start + 2
		name := strings.TrimSpace(remaining[start+2 : end])
		value, exists := variables[name]
		if !exists {
			return "", fmt.Errorf("提示词 %q 使用了未知占位符 %q", id, name)
		}
		output.WriteString(remaining[:start])
		output.WriteString(value)
		remaining = remaining[end+2:]
	}
	result := strings.TrimSpace(output.String())
	if result == "" || len(result) > maxPromptBytes || strings.ContainsRune(result, '\x00') {
		return "", fmt.Errorf("提示词 %q 渲染后为空、过长或包含 NUL", id)
	}
	return result, nil
}
