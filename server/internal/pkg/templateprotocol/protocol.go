package templateprotocol

import (
	"sort"
	"strings"
)

var executionBlockAliases = map[string]string{
	"requests":    "http",
	"http":        "http",
	"https":       "http",
	"tcp":         "tcp",
	"network":     "tcp",
	"dns":         "dns",
	"ssl":         "ssl",
	"tls":         "ssl",
	"file":        "file",
	"headless":    "headless",
	"javascript":  "javascript",
	"code":        "code",
	"workflows":   "workflows",
	"workflow":    "workflows",
	"websocket":   "websocket",
	"whois":       "whois",
	"offlinehttp": "offlinehttp",
}

// Normalize maps template execution block aliases to the protocol value exposed by server APIs.
func Normalize(value string) string {
	return executionBlockAliases[strings.ToLower(strings.TrimSpace(value))]
}

// NormalizeList normalizes a list of protocol values and removes blanks and duplicates.
func NormalizeList(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := Normalize(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

// MatchValues returns normalized protocol values plus legacy aliases used by older persisted data.
func MatchValues(values []string) []string {
	normalized := NormalizeList(values)
	result := make([]string, 0, len(normalized))
	seen := make(map[string]struct{}, len(normalized))

	appendValue := func(value string) {
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	for _, value := range normalized {
		appendValue(value)
		switch value {
		case "http":
			appendValue("https")
			appendValue("requests")
		case "tcp":
			appendValue("network")
		case "ssl":
			appendValue("tls")
		case "workflows":
			appendValue("workflow")
		}
	}
	return result
}

// CollectFromTopLevelKeys detects protocols from YAML top-level execution block keys only.
func CollectFromTopLevelKeys(keys map[string]struct{}) []string {
	values := make([]string, 0, len(keys))
	for key := range keys {
		values = append(values, key)
	}

	result := NormalizeList(values)
	sort.Strings(result)
	return result
}
