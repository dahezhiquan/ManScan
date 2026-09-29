package assetdomainfingerprint

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"strings"
)

// CacheEnv stores the preflight asset-domain fingerprint cache path.
const CacheEnv = "MANSCAN_ASSET_DOMAIN_FINGERPRINT_CACHE"

// Component is a technology fingerprint component from the preflight cache.
type Component struct {
	Domain     string `json:"domain"`
	AppName    string `json:"app_name"`
	AppVersion string `json:"app_version"`
}

// Entry is one target record in the preflight asset-domain fingerprint cache.
type Entry struct {
	Target     string      `json:"target"`
	Domain     string      `json:"domain"`
	HTTPAlive  *bool       `json:"http_alive"`
	Components []Component `json:"components"`
}

// State is the normalized cache state for one target key.
type State struct {
	Components     []Component
	HTTPAlive      bool
	HTTPAliveKnown bool
}

// Cache stores normalized asset-domain fingerprint records keyed by target.
type Cache struct {
	states map[string]State
}

// LoadFromEnv loads the cache from CacheEnv.
func LoadFromEnv() *Cache {
	return Load(strings.TrimSpace(os.Getenv(CacheEnv)))
}

// Load reads a cache file from disk.
func Load(path string) *Cache {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}
	return FromEntries(entries)
}

// FromEntries builds a normalized cache from raw entries.
func FromEntries(entries []Entry) *Cache {
	if len(entries) == 0 {
		return nil
	}
	states := make(map[string]State, len(entries)*2)
	for _, entry := range entries {
		state := State{Components: dedupeComponents(entry.Components)}
		if entry.HTTPAlive != nil {
			state.HTTPAlive = *entry.HTTPAlive
			state.HTTPAliveKnown = true
		}
		for _, key := range []string{
			CacheKey(entry.Target),
			CacheKey(entry.Domain),
		} {
			if key == "" {
				continue
			}
			states[key] = state
		}
	}
	if len(states) == 0 {
		return nil
	}
	return &Cache{states: states}
}

// Lookup returns the normalized cache state for a target-like value.
func (c *Cache) Lookup(value string) (State, bool) {
	if c == nil || len(c.states) == 0 {
		return State{}, false
	}
	state, ok := c.states[CacheKey(value)]
	return state, ok
}

// HTTPProbeFailed reports whether preflight HTTP probing is known to have failed.
func (c *Cache) HTTPProbeFailed(value string) bool {
	state, ok := c.Lookup(value)
	return ok && state.HTTPAliveKnown && !state.HTTPAlive
}

// CacheKey normalizes target-like values into cache lookup keys.
func CacheKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if endpoint := endpointKey(value); endpoint != "" {
		return endpoint
	}
	return strings.ToLower(value)
}

func endpointKey(value string) string {
	parsed, ok := parseEndpoint(value)
	if !ok {
		return ""
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return ""
	}
	port := strings.TrimSpace(parsed.Port())
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	if port == "" {
		return strings.ToLower(host)
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return strings.ToLower(net.JoinHostPort(host, port))
}

func parseEndpoint(value string) (*url.URL, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, false
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.Host != "" {
		return parsed, true
	}
	parsed, err = url.Parse("scheme://" + value)
	if err == nil && parsed.Host != "" {
		return parsed, true
	}
	return nil, false
}

func dedupeComponents(values []Component) []Component {
	result := make([]Component, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.Domain = strings.TrimSpace(value.Domain)
		value.AppName = strings.TrimSpace(value.AppName)
		value.AppVersion = strings.TrimSpace(value.AppVersion)
		if value.AppName == "" {
			continue
		}
		key := strings.ToLower(value.Domain) + "\x00" + strings.ToLower(value.AppName)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}
