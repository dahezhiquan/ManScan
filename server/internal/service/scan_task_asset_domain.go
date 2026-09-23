package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"ManScan/pkg/utils"
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/scanruntime"
	"ManScan/server/internal/repository"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/useragent"
)

var errScanTaskPausedBeforeProcess = errors.New("scan task paused before scanner process started")

func (s *scanTaskService) syncAliveAssetDomainsBeforeScan(ctx context.Context, request dto.CreateScanTaskRequest, targets []string, state *scanruntime.State) error {
	if s.assetDomainRepository == nil || len(targets) == 0 {
		return nil
	}
	if request.OfflineHTTP || request.DisableHTTPProbe {
		return nil
	}

	if state != nil {
		state.Append("info", "asset_domain_probe_started", "开始扫描前域名资产存活探测")
	}
	networkItems, err := s.assetDomainRepository.ListNetworkItems(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		if s.logger != nil {
			s.logger.Error("load asset domain network config failed", "error", err)
		}
		if state != nil {
			state.Append("warn", "asset_domain_probe_config_failed", "扫描前域名资产存活探测失败，已跳过资产同步")
		}
		return nil
	}

	probeResult, err := probeAssetDomainLiveness(ctx, request, targets, buildAssetDomainNetworkRegions(networkItems))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		if s.logger != nil {
			s.logger.Error("probe asset domains before scan failed", "error", err)
		}
		if state != nil {
			state.Append("warn", "asset_domain_probe_failed", "扫描前域名资产存活探测失败，已跳过资产同步")
		}
		return nil
	}
	if len(probeResult.CheckedDomains) == 0 {
		if state != nil {
			state.Append("info", "asset_domain_probe_finished", assetDomainProbeFinishedMessage(0, 0))
		}
		return nil
	}

	if err := s.assetDomainRepository.SyncObservations(ctx, probeResult.Observations, probeResult.CheckedDomains, time.Now()); err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		if s.logger != nil {
			s.logger.Error("sync probed asset domain liveness failed", "alive_domain_count", len(probeResult.Observations), "checked_domain_count", len(probeResult.CheckedDomains), "error", err)
		}
		if state != nil {
			state.Append("warn", "asset_domain_probe_sync_failed", "扫描前域名资产存活探测完成，但同步资产表失败")
		}
		return nil
	}
	if state != nil {
		aliveCount := len(probeResult.Observations)
		notAliveCount := len(probeResult.CheckedDomains) - aliveCount
		if notAliveCount < 0 {
			notAliveCount = 0
		}
		state.Append("info", "asset_domain_probe_finished", assetDomainProbeFinishedMessage(aliveCount, notAliveCount))
	}
	return nil
}

func assetDomainProbeFinishedMessage(aliveCount, notAliveCount int) string {
	return fmt.Sprintf("扫描前域名资产存活探测完成，本次扫描存活 %d 个，不存活 %d 个", aliveCount, notAliveCount)
}

type assetDomainLivenessProbeResult struct {
	Observations   []repository.AssetDomainObservation
	CheckedDomains []string
}

type assetDomainNetworkRegion struct {
	prefix netip.Prefix
	region string
}

func probeAssetDomainLiveness(ctx context.Context, request dto.CreateScanTaskRequest, targets []string, networkRegions []assetDomainNetworkRegion) (assetDomainLivenessProbeResult, error) {
	httpxOptions := httpx.DefaultOptions
	httpxOptions.RetryMax = request.Retries
	httpxOptions.Timeout = time.Duration(defaultInt(request.Timeout, 10)) * time.Second
	httpxOptions.FollowRedirects = true
	httpxOptions.MaxRedirects = defaultInt(request.MaxRedirects, httpxOptions.MaxRedirects)
	httpxOptions.MaxResponseBodySizeToRead = int64(defaultInt(request.ResponseReadSize, 1024*1024))
	if proxy := firstCleanString(request.Proxy); proxy != "" {
		httpxOptions.Proxy = proxy
	}

	httpxClient, err := httpx.New(&httpxOptions)
	if err != nil {
		return assetDomainLivenessProbeResult{}, err
	}
	defer func() {
		if httpxClient.Dialer != nil {
			httpxClient.Dialer.Close()
		}
	}()

	concurrency := request.ProbeConcurrency
	if concurrency <= 0 {
		concurrency = defaultInt(request.BulkSize, 50)
	}
	if concurrency <= 0 {
		concurrency = 50
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	sem := make(chan struct{}, concurrency)
	results := make(chan assetDomainProbeTargetResult, len(targets))
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	setFirstErr := func(err error) {
		errMu.Lock()
		defer errMu.Unlock()
		if firstErr == nil {
			firstErr = err
		}
	}

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			setFirstErr(err)
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			result, err := probeAssetDomainTarget(ctx, httpxClient, target, networkRegions)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					setFirstErr(err)
				}
				return
			}
			if len(result.CheckedDomains) > 0 {
				results <- result
			}
		}(target)
	}

	wg.Wait()
	close(results)
	errMu.Lock()
	probeErr := firstErr
	errMu.Unlock()
	if probeErr != nil {
		return assetDomainLivenessProbeResult{}, probeErr
	}

	observationSeen := make(map[string]struct{}, len(results))
	checkedSeen := make(map[string]struct{}, len(results))
	probeResult := assetDomainLivenessProbeResult{}
	for result := range results {
		for _, observation := range result.Observations {
			if _, ok := observationSeen[observation.Domain]; ok {
				continue
			}
			observationSeen[observation.Domain] = struct{}{}
			probeResult.Observations = append(probeResult.Observations, observation)
		}
		for _, domain := range result.CheckedDomains {
			if _, ok := checkedSeen[domain]; ok {
				continue
			}
			checkedSeen[domain] = struct{}{}
			probeResult.CheckedDomains = append(probeResult.CheckedDomains, domain)
		}
	}
	return probeResult, nil
}

type assetDomainProbeTargetResult struct {
	Observations   []repository.AssetDomainObservation
	CheckedDomains []string
}

func probeAssetDomainTarget(ctx context.Context, httpxClient *httpx.HTTPX, target string, networkRegions []assetDomainNetworkRegion) (assetDomainProbeTargetResult, error) {
	result := assetDomainProbeTargetResult{}
	for _, probeURL := range assetDomainProbeURLs(target) {
		if err := ctx.Err(); err != nil {
			return assetDomainProbeTargetResult{}, err
		}
		domain := canonicalAssetDomainFromURL(probeURL)
		if domain == "" {
			continue
		}
		result.CheckedDomains = append(result.CheckedDomains, domain)
		req, err := httpxClient.NewRequestWithContext(ctx, http.MethodGet, probeURL)
		if err != nil {
			continue
		}
		userAgent := useragent.PickRandom()
		req.Header.Set("User-Agent", userAgent.Raw)
		resp, err := httpxClient.Do(req, httpx.UnsafeOptions{})
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return assetDomainProbeTargetResult{}, err
			}
			continue
		}
		result.Observations = append(result.Observations, repository.AssetDomainObservation{
			Domain:         domain,
			Region:         assetDomainRegion(domain, networkRegions),
			HTTPStatusCode: firstAssetDomainHTTPStatusCode(resp),
			Title:          assetDomainResponseTitle(resp),
			Request:        finalAssetDomainRequest(resp),
			Response:       resp.Raw,
		})
		return result, nil
	}
	return result, nil
}

func buildAssetDomainNetworkRegions(items []repository.AssetDomainNetworkItem) []assetDomainNetworkRegion {
	regions := make([]assetDomainNetworkRegion, 0, len(items))
	for _, item := range items {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item.ItemName))
		if err != nil {
			continue
		}
		regions = append(regions, assetDomainNetworkRegion{
			prefix: prefix.Masked(),
			region: strings.TrimSpace(item.SmallCategory),
		})
	}
	return regions
}

func assetDomainRegion(domain string, networkRegions []assetDomainNetworkRegion) string {
	host := assetDomainHost(domain)
	if host == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		for _, region := range networkRegions {
			if region.prefix.Contains(addr) {
				return region.region
			}
		}
		return "外网"
	}
	if assetDomainHasInternalSuffix(host) {
		return "内网"
	}
	return "外网"
}

func assetDomainHost(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(domain)
	if err == nil {
		return strings.Trim(strings.ToLower(host), "[]")
	}
	return strings.Trim(strings.ToLower(domain), "[]")
}

func assetDomainHasInternalSuffix(host string) bool {
	for _, label := range strings.Split(strings.ToLower(strings.TrimSpace(host)), ".") {
		if strings.HasSuffix(label, "-int") {
			return true
		}
	}
	return false
}

func firstAssetDomainHTTPStatusCode(resp *httpx.Response) uint {
	if resp == nil {
		return 0
	}
	for _, item := range resp.Chain {
		if item.StatusCode > 0 {
			return uint(item.StatusCode)
		}
	}
	if resp.StatusCode > 0 {
		return uint(resp.StatusCode)
	}
	return 0
}

func assetDomainResponseTitle(resp *httpx.Response) string {
	if resp == nil {
		return ""
	}
	return httpx.ExtractTitle(resp)
}

func finalAssetDomainRequest(resp *httpx.Response) string {
	if resp == nil {
		return ""
	}
	for i := len(resp.Chain) - 1; i >= 0; i-- {
		if request := strings.TrimSpace(string(resp.Chain[i].Request)); request != "" {
			return request
		}
	}
	return ""
}

func assetDomainProbeURLs(target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{target}
	}

	normalized := normalizeAssetProbeInput(target)
	schemes := utils.DetermineSchemeOrder(normalized)
	result := make([]string, 0, len(schemes))
	for _, scheme := range schemes {
		result = append(result, fmt.Sprintf("%s://%s", scheme, normalized))
	}
	return result
}

func normalizeAssetProbeInput(input string) string {
	if strings.Contains(input, "://") || strings.HasPrefix(input, "[") {
		return input
	}
	addr, err := netip.ParseAddr(input)
	if err != nil || !addr.Is6() {
		return input
	}
	return fmt.Sprintf("[%s]", addr.String())
}

func canonicalAssetDomainFromURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return ""
	}

	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
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
		return host
	}
	if value, err := strconv.Atoi(port); err != nil || value < 1 || value > 65535 {
		return ""
	}
	return net.JoinHostPort(host, port)
}

func firstCleanString(values []string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
