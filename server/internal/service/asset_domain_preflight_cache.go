package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/repository"
)

const assetDomainPreflightCacheVersion = 1

type assetDomainPreflightCache struct {
	Version   int                          `json:"version"`
	UpdatedAt time.Time                    `json:"updated_at"`
	Targets   []assetDomainPreflightTarget `json:"targets"`
}

type assetDomainPreflightTarget struct {
	Target                         string                                          `json:"target"`
	ProbeDone                      bool                                            `json:"probe_done"`
	WappalyzerDone                 bool                                            `json:"wappalyzer_done"`
	ActiveFingerprintDone          bool                                            `json:"active_fingerprint_done"`
	CheckedDomains                 []string                                        `json:"checked_domains"`
	Observations                   []repository.AssetDomainObservation             `json:"observations"`
	WappalyzerServiceAssets        []repository.AssetDomainServiceAssetObservation `json:"wappalyzer_service_assets"`
	ActiveFingerprintServiceAssets []repository.AssetDomainServiceAssetObservation `json:"active_fingerprint_service_assets"`
	Fingerprints                   []assetDomainFingerprintCacheEntry              `json:"fingerprints"`
	FingerprintTargets             []assetDomainFingerprintTarget                  `json:"fingerprint_targets"`
	UnresponsiveFingerprintTargets []assetDomainFingerprintTarget                  `json:"unresponsive_fingerprint_targets"`
}

func readAssetDomainPreflightCache(path string) (*assetDomainPreflightCache, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &assetDomainPreflightCache{Version: assetDomainPreflightCacheVersion}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &assetDomainPreflightCache{Version: assetDomainPreflightCacheVersion}, nil
		}
		return nil, err
	}
	var cache assetDomainPreflightCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	if cache.Version == 0 {
		cache.Version = assetDomainPreflightCacheVersion
	}
	cache.normalize()
	return &cache, nil
}

func writeAssetDomainPreflightCache(path string, cache *assetDomainPreflightCache) error {
	path = strings.TrimSpace(path)
	if path == "" || cache == nil {
		return nil
	}
	cache.Version = assetDomainPreflightCacheVersion
	cache.UpdatedAt = time.Now()
	cache.normalize()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (c *assetDomainPreflightCache) splitCompletedTargets(targets []string, request dto.CreateScanTaskRequest) (assetDomainLivenessProbeResult, []string) {
	if c == nil || len(targets) == 0 {
		return assetDomainLivenessProbeResult{}, targets
	}
	entries := c.entryMap()
	completed := assetDomainLivenessProbeResult{}
	pending := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		entry, ok := entries[assetDomainPreflightTargetKey(target)]
		if !ok || !entry.completeFor(request) {
			pending = append(pending, target)
			continue
		}
		completed.merge(entry.result())
	}
	completed.normalize()
	return completed, pending
}

func (c *assetDomainPreflightCache) upsertProbeResults(results []assetDomainProbeTargetResult) {
	if c == nil || len(results) == 0 {
		return
	}
	entries := c.entryMap()
	for _, result := range results {
		target := strings.TrimSpace(result.Target)
		if target == "" {
			continue
		}
		key := assetDomainPreflightTargetKey(target)
		entry := entries[key]
		entry.Target = target
		entry.ProbeDone = true
		entry.WappalyzerDone = true
		entry.CheckedDomains = uniqueNonEmptyStrings(result.CheckedDomains)
		entry.Observations = uniqueAssetDomainObservations(result.Observations)
		entry.WappalyzerServiceAssets = uniqueAssetDomainServiceAssetObservations(result.ServiceAssets)
		entry.Fingerprints = uniqueAssetDomainFingerprintCacheEntries(result.Fingerprints)
		entry.FingerprintTargets = uniqueAssetDomainFingerprintTargets(result.FingerprintTargets)
		entry.UnresponsiveFingerprintTargets = uniqueAssetDomainFingerprintTargets(result.UnresponsiveFingerprintTargets)
		entries[key] = entry
	}
	c.targetsFromMap(entries)
}

func (c *assetDomainPreflightCache) markActiveFingerprintDone(targets []assetDomainFingerprintTarget, observations []repository.AssetDomainServiceAssetObservation) {
	if c == nil || len(targets) == 0 {
		return
	}
	entries := c.entryMap()
	for _, target := range targets {
		targetDomain := strings.TrimSpace(target.Domain)
		if targetDomain == "" {
			continue
		}
		for key, entry := range entries {
			if !entry.hasDomain(targetDomain) {
				continue
			}
			entry.ActiveFingerprintDone = true
			entry.ActiveFingerprintServiceAssets = uniqueAssetDomainServiceAssetObservations(append(
				entry.ActiveFingerprintServiceAssets,
				filterAssetDomainServiceAssetsByDomain(observations, targetDomain)...,
			))
			entries[key] = entry
		}
	}
	c.targetsFromMap(entries)
}

func (c *assetDomainPreflightCache) pendingFingerprintTargets(request dto.CreateScanTaskRequest, targets []string) ([]assetDomainFingerprintTarget, []assetDomainFingerprintTarget) {
	if c == nil || len(targets) == 0 || request.AutomaticScan {
		return nil, nil
	}
	entries := c.entryMap()
	activeTargets := make([]assetDomainFingerprintTarget, 0, len(targets))
	unresponsiveTargets := make([]assetDomainFingerprintTarget, 0, len(targets))
	for _, target := range targets {
		entry, ok := entries[assetDomainPreflightTargetKey(target)]
		if !ok || entry.ActiveFingerprintDone {
			continue
		}
		activeTargets = append(activeTargets, entry.FingerprintTargets...)
		unresponsiveTargets = append(unresponsiveTargets, entry.UnresponsiveFingerprintTargets...)
	}
	return uniqueAssetDomainFingerprintTargets(activeTargets), uniqueAssetDomainFingerprintTargets(unresponsiveTargets)
}

func (c *assetDomainPreflightCache) entryMap() map[string]assetDomainPreflightTarget {
	entries := make(map[string]assetDomainPreflightTarget, len(c.Targets))
	for _, entry := range c.Targets {
		entry.normalize()
		if entry.Target == "" {
			continue
		}
		entries[assetDomainPreflightTargetKey(entry.Target)] = entry
	}
	return entries
}

func (c *assetDomainPreflightCache) targetsFromMap(entries map[string]assetDomainPreflightTarget) {
	c.Targets = c.Targets[:0]
	for _, entry := range entries {
		entry.normalize()
		if entry.Target == "" {
			continue
		}
		c.Targets = append(c.Targets, entry)
	}
	c.normalize()
}

func (c *assetDomainPreflightCache) normalize() {
	if c == nil {
		return
	}
	entries := make(map[string]assetDomainPreflightTarget, len(c.Targets))
	for _, entry := range c.Targets {
		entry.normalize()
		if entry.Target == "" {
			continue
		}
		entries[assetDomainPreflightTargetKey(entry.Target)] = entry
	}
	c.Targets = c.Targets[:0]
	for _, entry := range entries {
		c.Targets = append(c.Targets, entry)
	}
}

func (t *assetDomainPreflightTarget) normalize() {
	t.Target = strings.TrimSpace(t.Target)
	t.CheckedDomains = uniqueNonEmptyStrings(t.CheckedDomains)
	t.Observations = uniqueAssetDomainObservations(t.Observations)
	t.WappalyzerServiceAssets = uniqueAssetDomainServiceAssetObservations(t.WappalyzerServiceAssets)
	t.ActiveFingerprintServiceAssets = uniqueAssetDomainServiceAssetObservations(t.ActiveFingerprintServiceAssets)
	t.Fingerprints = uniqueAssetDomainFingerprintCacheEntries(t.Fingerprints)
	t.FingerprintTargets = uniqueAssetDomainFingerprintTargets(t.FingerprintTargets)
	t.UnresponsiveFingerprintTargets = uniqueAssetDomainFingerprintTargets(t.UnresponsiveFingerprintTargets)
}

func (t assetDomainPreflightTarget) completeFor(request dto.CreateScanTaskRequest) bool {
	if !t.ProbeDone || !t.WappalyzerDone {
		return false
	}
	if request.AutomaticScan {
		return true
	}
	return t.ActiveFingerprintDone
}

func (t assetDomainPreflightTarget) result() assetDomainLivenessProbeResult {
	return assetDomainLivenessProbeResult{
		Observations:                   uniqueAssetDomainObservations(t.Observations),
		CheckedDomains:                 uniqueNonEmptyStrings(t.CheckedDomains),
		ServiceAssets:                  uniqueAssetDomainServiceAssetObservations(append(append([]repository.AssetDomainServiceAssetObservation(nil), t.WappalyzerServiceAssets...), t.ActiveFingerprintServiceAssets...)),
		Fingerprints:                   uniqueAssetDomainFingerprintCacheEntries(t.Fingerprints),
		FingerprintTargets:             uniqueAssetDomainFingerprintTargets(t.FingerprintTargets),
		UnresponsiveFingerprintTargets: uniqueAssetDomainFingerprintTargets(t.UnresponsiveFingerprintTargets),
	}
}

func (t assetDomainPreflightTarget) hasDomain(domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}
	for _, value := range t.CheckedDomains {
		if strings.EqualFold(strings.TrimSpace(value), domain) {
			return true
		}
	}
	for _, value := range t.FingerprintTargets {
		if strings.EqualFold(strings.TrimSpace(value.Domain), domain) {
			return true
		}
	}
	for _, value := range t.UnresponsiveFingerprintTargets {
		if strings.EqualFold(strings.TrimSpace(value.Domain), domain) {
			return true
		}
	}
	return false
}

func assetDomainPreflightTargetKey(target string) string {
	return strings.ToLower(strings.TrimSpace(target))
}

func filterAssetDomainServiceAssetsByDomain(values []repository.AssetDomainServiceAssetObservation, domain string) []repository.AssetDomainServiceAssetObservation {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil
	}
	result := make([]repository.AssetDomainServiceAssetObservation, 0, len(values))
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value.Domain), domain) {
			result = append(result, value)
		}
	}
	return uniqueAssetDomainServiceAssetObservations(result)
}
