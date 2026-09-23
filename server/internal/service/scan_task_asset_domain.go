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
	probeResult, err := probeAssetDomainLiveness(ctx, request, targets)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		if s.logger != nil {
			s.logger.Error("probe asset domains before scan failed", "error", err)
		}
		return nil
	}
	if len(probeResult.CheckedDomains) == 0 {
		if state != nil {
			state.Append("info", "asset_domain_probe_finished", "扫描前域名资产存活探测完成，未发现可同步域名资产")
		}
		return nil
	}

	if err := s.assetDomainRepository.SyncLiveness(ctx, probeResult.AliveDomains, probeResult.CheckedDomains, time.Now()); err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		if s.logger != nil {
			s.logger.Error("sync probed asset domain liveness failed", "alive_domain_count", len(probeResult.AliveDomains), "checked_domain_count", len(probeResult.CheckedDomains), "error", err)
		}
		return nil
	}
	if state != nil {
		state.Append("info", "asset_domain_probe_finished", fmt.Sprintf("扫描前域名资产存活探测完成，已同步 %d 个存活域名资产，检查 %d 个域名资产", len(probeResult.AliveDomains), len(probeResult.CheckedDomains)))
	}
	return nil
}

type assetDomainLivenessProbeResult struct {
	AliveDomains   []string
	CheckedDomains []string
}

func probeAssetDomainLiveness(ctx context.Context, request dto.CreateScanTaskRequest, targets []string) (assetDomainLivenessProbeResult, error) {
	httpxOptions := httpx.DefaultOptions
	httpxOptions.RetryMax = request.Retries
	httpxOptions.Timeout = time.Duration(defaultInt(request.Timeout, 10)) * time.Second
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

			result, err := probeAssetDomainTarget(ctx, httpxClient, target)
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

	aliveSeen := make(map[string]struct{}, len(results))
	checkedSeen := make(map[string]struct{}, len(results))
	probeResult := assetDomainLivenessProbeResult{}
	for result := range results {
		for _, domain := range result.AliveDomains {
			if _, ok := aliveSeen[domain]; ok {
				continue
			}
			aliveSeen[domain] = struct{}{}
			probeResult.AliveDomains = append(probeResult.AliveDomains, domain)
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
	AliveDomains   []string
	CheckedDomains []string
}

func probeAssetDomainTarget(ctx context.Context, httpxClient *httpx.HTTPX, target string) (assetDomainProbeTargetResult, error) {
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
		req, err := httpxClient.NewRequestWithContext(ctx, http.MethodHead, probeURL)
		if err != nil {
			continue
		}
		userAgent := useragent.PickRandom()
		req.Header.Set("User-Agent", userAgent.Raw)
		if _, err := httpxClient.Do(req, httpx.UnsafeOptions{}); err != nil {
			if errors.Is(err, context.Canceled) {
				return assetDomainProbeTargetResult{}, err
			}
			continue
		}
		result.AliveDomains = append(result.AliveDomains, domain)
		return result, nil
	}
	return result, nil
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
