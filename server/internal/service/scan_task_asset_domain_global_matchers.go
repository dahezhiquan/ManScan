package service

import (
	"encoding/json"
	"net/textproto"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"ManScan/pkg/catalog/config"
	"ManScan/pkg/catalog/disk"
	"ManScan/pkg/model"
	"ManScan/pkg/operators"
	"ManScan/pkg/output"
	"ManScan/pkg/protocols"
	"ManScan/pkg/protocols/common/globalmatchers"
	"ManScan/pkg/protocols/common/protocolinit"
	nucleihttp "ManScan/pkg/protocols/http"
	"ManScan/pkg/templates"
	"ManScan/pkg/types"
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/scanruntime"
)

const assetDomainPreflightTemplateID = "asset-domain-preflight"

type assetDomainPreflightGlobalMatchers struct {
	storage *globalmatchers.Storage
}

func compileAssetDomainPreflightGlobalMatchers(templateDir string, request dto.CreateScanTaskRequest) (*assetDomainPreflightGlobalMatchers, error) {
	if !request.EnableGlobalMatchersTemplates {
		return nil, nil
	}
	templateDir = strings.TrimSpace(templateDir)
	if templateDir == "" {
		return nil, nil
	}

	paths, err := assetDomainGlobalMatcherTemplatePaths(templateDir)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, nil
	}

	storage := globalmatchers.New()
	options := &types.Options{
		EnableGlobalMatchersTemplates: true,
		NoColor:                       true,
		ResponseSaveSize:              defaultInt(request.ResponseSaveSize, assetDomainWappalyzerMaxBody),
		ExecutionId:                   "asset-domain-preflight-global-matchers-" + strconv.FormatInt(time.Now().UnixNano(), 10),
	}
	if err := protocolinit.Init(options); err != nil {
		return nil, err
	}
	defer protocolinit.Close(options.ExecutionId)
	executerOptions := &protocols.ExecutorOptions{
		Options:        options,
		Catalog:        disk.NewCatalog(templateDir),
		Parser:         templates.NewParser(),
		GlobalMatchers: storage,
	}
	for _, path := range paths {
		if _, err := templates.Parse(path, nil, executerOptions); err != nil {
			return nil, err
		}
	}
	if !storage.HasMatchers() {
		return nil, nil
	}
	return &assetDomainPreflightGlobalMatchers{storage: storage}, nil
}

func assetDomainGlobalMatchersTemplateDir() string {
	if root := strings.TrimSpace(config.DefaultConfig.GetTemplateDir()); root != "" {
		return root
	}
	return strings.TrimSpace(config.DefaultConfig.TemplatesDirectory)
}

func assetDomainGlobalMatcherTemplatePaths(templateDir string) ([]string, error) {
	templateDir = filepath.Clean(templateDir)
	candidateRoot := filepath.Join(templateDir, "http", "global-matchers")
	roots := []string{candidateRoot}
	if _, err := os.Stat(candidateRoot); err != nil {
		roots = []string{templateDir}
	}

	seen := make(map[string]struct{})
	paths := make([]string, 0, 8)
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return walkErr
			}
			if !config.IsTemplateWithRoot(path, templateDir) {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !assetDomainTemplateDeclaresGlobalMatchers(data) {
				return nil
			}
			if _, ok := seen[path]; ok {
				return nil
			}
			seen[path] = struct{}{}
			paths = append(paths, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func assetDomainTemplateDeclaresGlobalMatchers(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if strings.HasPrefix(trimmed, "global-matchers:") {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "global-matchers:"))
			if strings.EqualFold(value, "true") {
				return true
			}
		}
	}
	return false
}

func assetDomainPreflightVulnerabilityQueue(runtime *scanTaskRuntime) *vulnerabilityQueue {
	if runtime == nil {
		return nil
	}
	return runtime.vulnerabilityQueue
}

func runAssetDomainPreflightGlobalMatchers(state *scanruntime.State, matcherSet *assetDomainPreflightGlobalMatchers, vulnerabilityQueue *vulnerabilityQueue, originalTarget, probeURL, domain string, resp *assetDomainProbeHTTPResponse) {
	if state == nil || matcherSet == nil || matcherSet.storage == nil || !matcherSet.storage.HasMatchers() || resp == nil {
		return
	}

	request := &nucleihttp.Request{}
	event := assetDomainPreflightGlobalMatcherEvent(originalTarget, probeURL, domain, resp)
	matcherSet.storage.Match(event, request.Match, request.Extract, false, func(event output.InternalEvent, result *operators.Result) {
		for _, payload := range assetDomainPreflightGlobalMatcherPayloads(event, result, resp) {
			tags := scanruntime.ResultTagsFromInfo(assetDomainPayloadInfoMap(payload["info"]))
			metadata := scanruntime.ResultLogMetadataFromJSONPayload(payload, tags)
			templateName := scanruntime.AsString(assetDomainPayloadInfoMap(payload["info"])["name"])
			severity := scanruntime.AsString(assetDomainPayloadInfoMap(payload["info"])["severity"])
			templateID := scanruntime.FirstNonEmpty(scanruntime.AsString(payload["template-id"]), "unknown-template")
			if !state.RecordResult(templateID, templateName, severity, tags, metadata.ResultKey) {
				continue
			}
			state.AppendResult(scanruntime.FormatJSONResultMessage(payload), tags, metadata)
			if vulnerabilityQueue != nil {
				vulnerabilityQueue.Enqueue(vulnerabilityResultEvent{
					taskID:   state.ID,
					taskName: state.TaskName,
					payload:  clonePayload(payload),
				})
			}
		}
	})
}

func assetDomainPreflightGlobalMatcherEvent(originalTarget, probeURL, domain string, resp *assetDomainProbeHTTPResponse) output.InternalEvent {
	matchedURL := firstNonEmpty(resp.Input, probeURL, originalTarget)
	body := string(resp.Data)
	headers := assetDomainPreflightHeaderString(resp)
	event := output.InternalEvent{
		"template-id":   assetDomainPreflightTemplateID,
		"template-info": model.Info{Name: "Asset Domain Preflight"},
		"template-path": assetDomainPreflightTemplateID,
		"type":          "http",
		"input":         firstNonEmpty(originalTarget, probeURL, matchedURL),
		"host":          firstNonEmpty(probeURL, matchedURL, originalTarget),
		"matched":       matchedURL,
		"url":           matchedURL,
		"domain":        domain,
		"status_code":   resp.StatusCode,
		"body":          body,
		"all_headers":   headers,
		"header":        headers,
		"request":       resp.Request,
		"response":      resp.Raw,
		"duration":      float64(0),
	}
	for name, values := range resp.Headers {
		normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
		if normalized == "" {
			continue
		}
		event[normalized] = strings.Join(values, " ")
	}
	return event
}

func assetDomainPreflightGlobalMatcherPayloads(event output.InternalEvent, result *operators.Result, resp *assetDomainProbeHTTPResponse) []map[string]interface{} {
	if result == nil {
		return nil
	}
	if len(result.DynamicValues) > 0 && !result.Matched {
		return nil
	}
	if result.Operators != nil && (len(result.Extracts) > 0 || len(result.OutputExtracts) > 0) && len(result.Operators.Matchers) > 0 && !result.Matched {
		return nil
	}

	payloads := make([]map[string]interface{}, 0, len(result.Matches)+len(result.Extracts)+1)
	if len(result.Matches) > 0 {
		for name := range result.Matches {
			payload := assetDomainPreflightGlobalMatcherPayload(event, result.OutputExtracts, resp)
			payload["matcher-name"] = name
			payloads = append(payloads, payload)
		}
		return payloads
	}
	if len(result.Extracts) > 0 {
		for name, values := range result.Extracts {
			payload := assetDomainPreflightGlobalMatcherPayload(event, values, resp)
			payload["extractor-name"] = name
			payloads = append(payloads, payload)
		}
		return payloads
	}

	payloads = append(payloads, assetDomainPreflightGlobalMatcherPayload(event, result.OutputExtracts, resp))
	return payloads
}

func assetDomainPreflightGlobalMatcherPayload(event output.InternalEvent, extractedResults []string, resp *assetDomainProbeHTTPResponse) map[string]interface{} {
	info := assetDomainInfoToPayloadMap(event["template-info"])
	matchedURL := scanruntime.FirstNonEmpty(scanruntime.AsString(event["matched"]), scanruntime.AsString(event["url"]), scanruntime.AsString(event["host"]))
	payload := map[string]interface{}{
		"template-id":     scanruntime.AsString(event["template-id"]),
		"template-path":   scanruntime.AsString(event["template-path"]),
		"info":            info,
		"type":            scanruntime.AsString(event["type"]),
		"host":            scanruntime.AsString(event["host"]),
		"matched-at":      matchedURL,
		"url":             matchedURL,
		"input":           scanruntime.AsString(event["input"]),
		"timestamp":       time.Now(),
		"matcher-status":  true,
		"global-matchers": true,
		"request":         assetDomainPreflightHistoryJSON(resp.Request),
		"response":        assetDomainPreflightHistoryJSON(resp.Raw),
	}
	if len(extractedResults) > 0 {
		payload["extracted-results"] = extractedResults
	}
	return payload
}

func assetDomainInfoToPayloadMap(value interface{}) map[string]interface{} {
	if info, ok := value.(model.Info); ok {
		encoded, err := json.Marshal(info)
		if err != nil {
			return map[string]interface{}{}
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(encoded, &payload); err != nil {
			return map[string]interface{}{}
		}
		return payload
	}
	return assetDomainPayloadInfoMap(value)
}

func assetDomainPayloadInfoMap(value interface{}) map[string]interface{} {
	if info, ok := value.(map[string]interface{}); ok {
		return info
	}
	return map[string]interface{}{}
}

func assetDomainPreflightHeaderString(resp *assetDomainProbeHTTPResponse) string {
	if resp == nil {
		return ""
	}
	if raw := resp.Raw; raw != "" {
		if index := strings.Index(raw, "\r\n\r\n"); index >= 0 {
			return raw[:index]
		}
		if index := strings.Index(raw, "\n\n"); index >= 0 {
			return raw[:index]
		}
	}
	keys := make([]string, 0, len(resp.Headers))
	for key := range resp.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		for _, value := range resp.Headers[key] {
			builder.WriteString(textproto.CanonicalMIMEHeaderKey(key))
			builder.WriteString(": ")
			builder.WriteString(value)
			builder.WriteString("\r\n")
		}
	}
	return strings.TrimSpace(builder.String())
}

func assetDomainPreflightHistoryJSON(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	encoded, err := json.Marshal(map[string]string{"1": value})
	if err != nil {
		return ""
	}
	return string(encoded)
}
