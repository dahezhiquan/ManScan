package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ManScan/pkg/utils"
	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/scanruntime"
	"ManScan/server/internal/repository"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/useragent"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

var errScanTaskPausedBeforeProcess = errors.New("scan task paused before scanner process started")

const (
	assetDomainFingerprintCacheEnv = "MANSCAN_ASSET_DOMAIN_FINGERPRINT_CACHE"
	assetDomainWappalyzerMaxBody   = 4 * 1024 * 1024
)

var assetDomainTitlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (s *scanTaskService) syncAliveAssetDomainsBeforeScan(ctx context.Context, request dto.CreateScanTaskRequest, targets []string, state *scanruntime.State, fingerprintCachePath string, serviceAssetQueue *assetDomainServiceAssetQueue) error {
	if s.assetDomainRepository == nil || len(targets) == 0 {
		return nil
	}
	if request.OfflineHTTP || request.DisableHTTPProbe {
		return nil
	}

	if state != nil {
		state.Append("info", "asset_domain_probe_started", "开始扫描前域名资产存活 & 指纹探测")
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

	if state != nil {
		state.Append("info", "asset_domain_wappalyzer_started", "开始进行 Wappalyzer 被动指纹识别")
	}
	probeResult, err := probeAssetDomainLiveness(ctx, request, targets, buildAssetDomainNetworkRegions(networkItems), state)
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
	if state != nil {
		state.Append("info", "asset_domain_wappalyzer_finished", "Wappalyzer 被动指纹识别完成，"+assetDomainComponentCountSummary(probeResult.ServiceAssets))
	}
	if serviceAssetQueue != nil {
		serviceAssetQueue.SetTargetResolver(newAssetDomainFingerprintTargetResolver(probeResult.FingerprintTargets))
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
	if err := s.assetDomainRepository.SyncServiceAssets(ctx, probeResult.ServiceAssets, probeResult.CheckedDomains, time.Now()); err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		if s.logger != nil {
			s.logger.Error("sync probed asset domain service assets failed", "service_asset_count", len(probeResult.ServiceAssets), "checked_domain_count", len(probeResult.CheckedDomains), "error", err)
		}
		if state != nil {
			state.Append("warn", "asset_domain_service_asset_sync_failed", "扫描前域名组件识别完成，但同步组件表失败")
		}
		return nil
	}
	if err := writeAssetDomainFingerprintCache(fingerprintCachePath, probeResult.Fingerprints); err != nil {
		if s.logger != nil {
			s.logger.Error("write asset domain fingerprint cache failed", "path", fingerprintCachePath, "error", err)
		}
	}
	if !request.AutomaticScan {
		if state != nil {
			state.Append("info", "asset_domain_fingerprint_template_started", "开始进行 ManScan 智能主动指纹识别")
		}
		activeServiceAssets, err := s.runAssetDomainFingerprintTemplates(ctx, request, probeResult.FingerprintTargets, filepath.Dir(fingerprintCachePath), state)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			if s.logger != nil {
				s.logger.Error("run asset domain fingerprint templates failed", "target_count", len(probeResult.FingerprintTargets), "error", err)
			}
			if state != nil {
				state.Append("warn", "asset_domain_fingerprint_template_failed", "扫描前域名组件指纹模板识别失败，已继续后续扫描")
			}
		} else if state != nil {
			state.Append("info", "asset_domain_fingerprint_template_finished", "智能主动指纹识别完成，"+assetDomainComponentCountSummary(activeServiceAssets))
		}
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
	return fmt.Sprintf("扫描前域名资产存活 & 指纹探测完成，本次扫描存活 %d 个，不存活 %d 个", aliveCount, notAliveCount)
}

func recordAssetDomainFingerprintObservations(state *scanruntime.State, values []repository.AssetDomainServiceAssetObservation) {
	if state == nil {
		return
	}
	for _, value := range uniqueAssetDomainServiceAssetObservations(values) {
		key := "asset-domain-fingerprint\x00" + value.Domain + "\x00" + normalizeAssetDomainComponentName(value.AppName)
		if !state.RecordResult("asset-domain-fingerprint", value.AppName, "info", []string{"tech"}, key) {
			continue
		}
		state.AppendResult(fmt.Sprintf("[域名组件指纹识别][info][%s] 命中 %s", value.AppName, value.Domain), []string{"tech"})
	}
}

func assetDomainComponentCountSummary(values []repository.AssetDomainServiceAssetObservation) string {
	return fmt.Sprintf("共识别到 %d 个组件", len(uniqueAssetDomainServiceAssetObservations(values)))
}

type assetDomainLivenessProbeResult struct {
	Observations       []repository.AssetDomainObservation
	CheckedDomains     []string
	ServiceAssets      []repository.AssetDomainServiceAssetObservation
	Fingerprints       []assetDomainFingerprintCacheEntry
	FingerprintTargets []assetDomainFingerprintTarget
}

type assetDomainFingerprintTarget struct {
	Input    string
	Domain   string
	FinalURL string
}

type assetDomainNetworkRegion struct {
	prefix netip.Prefix
	region string
}

func probeAssetDomainLiveness(ctx context.Context, request dto.CreateScanTaskRequest, targets []string, networkRegions []assetDomainNetworkRegion, state *scanruntime.State) (assetDomainLivenessProbeResult, error) {
	httpClient := newAssetDomainWappalyzerHTTPClient(request)
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		wappalyzerClient = nil
	}

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

			result, err := probeAssetDomainTarget(ctx, httpClient, wappalyzerClient, target, networkRegions, state)
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
		probeResult.ServiceAssets = append(probeResult.ServiceAssets, result.ServiceAssets...)
		probeResult.Fingerprints = append(probeResult.Fingerprints, result.Fingerprints...)
		probeResult.FingerprintTargets = append(probeResult.FingerprintTargets, result.FingerprintTargets...)
	}
	probeResult.ServiceAssets = uniqueAssetDomainServiceAssetObservations(probeResult.ServiceAssets)
	probeResult.Fingerprints = uniqueAssetDomainFingerprintCacheEntries(probeResult.Fingerprints)
	probeResult.FingerprintTargets = uniqueAssetDomainFingerprintTargets(probeResult.FingerprintTargets)
	return probeResult, nil
}

type assetDomainProbeTargetResult struct {
	Observations       []repository.AssetDomainObservation
	CheckedDomains     []string
	ServiceAssets      []repository.AssetDomainServiceAssetObservation
	Fingerprints       []assetDomainFingerprintCacheEntry
	FingerprintTargets []assetDomainFingerprintTarget
}

type assetDomainFingerprintCacheEntry struct {
	Target     string                                 `json:"target"`
	Domain     string                                 `json:"domain"`
	Components []assetDomainFingerprintCacheComponent `json:"components"`
}

type assetDomainFingerprintCacheComponent struct {
	Domain     string `json:"domain"`
	AppName    string `json:"app_name"`
	AppVersion string `json:"app_version"`
}

type assetDomainProbeHTTPResponse struct {
	Input           string
	StatusCode      int
	FirstStatusCode int
	Headers         map[string][]string
	Data            []byte
	Raw             string
	Request         string
}

type assetDomainProbeStatusRecorder struct {
	firstStatusCode atomic.Int64
}

type assetDomainProbeStatusRecorderKey struct{}

type assetDomainProbeStatsStateKey struct{}

type assetDomainProbeStatusTransport struct {
	base http.RoundTripper
}

func (t assetDomainProbeStatusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if state, ok := req.Context().Value(assetDomainProbeStatsStateKey{}).(*scanruntime.State); ok && state != nil {
		state.AddRequestStats(0, 1, 1, "扫描前域名资产存活 & 指纹探测进度更新")
	}
	resp, err := t.base.RoundTrip(req)
	if resp != nil && resp.StatusCode > 0 {
		if recorder, ok := req.Context().Value(assetDomainProbeStatusRecorderKey{}).(*assetDomainProbeStatusRecorder); ok && recorder != nil {
			recorder.firstStatusCode.CompareAndSwap(0, int64(resp.StatusCode))
		}
	}
	return resp, err
}

func probeAssetDomainTarget(ctx context.Context, httpClient *retryablehttp.Client, wappalyzerClient *wappalyzer.Wappalyze, target string, networkRegions []assetDomainNetworkRegion, state *scanruntime.State) (assetDomainProbeTargetResult, error) {
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
		resp, err := doAssetDomainWappalyzerRequest(ctx, httpClient, probeURL, state)
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
		components := assetDomainWappalyzerComponents(wappalyzerClient, domain, resp)
		recordAssetDomainFingerprintObservations(state, components)
		result.ServiceAssets = append(result.ServiceAssets, components...)
		if wappalyzerClient != nil {
			result.Fingerprints = append(result.Fingerprints, assetDomainFingerprintCacheEntry{
				Target:     target,
				Domain:     domain,
				Components: assetDomainFingerprintCacheComponents(components),
			})
		}
		result.FingerprintTargets = append(result.FingerprintTargets, assetDomainFingerprintTarget{
			Input:    firstNonEmpty(probeURL, target),
			Domain:   domain,
			FinalURL: resp.Input,
		})
		return result, nil
	}
	return result, nil
}

func newAssetDomainWappalyzerHTTPClient(request dto.CreateScanTaskRequest) *retryablehttp.Client {
	options := retryablehttp.DefaultOptionsSingle
	options.RetryMax = defaultInt(request.Retries, 1)
	options.Timeout = time.Duration(defaultInt(request.Timeout, 10)) * time.Second
	var proxyURL *url.URL
	if proxyValue := firstCleanString(request.Proxy); proxyValue != "" {
		if parsedProxyURL, err := url.Parse(proxyValue); err == nil {
			proxyURL = parsedProxyURL
		}
	}
	options.WrapTransport = func(base http.RoundTripper) http.RoundTripper {
		transport := base
		if proxyURL != nil {
			if httpTransport, ok := base.(*http.Transport); ok {
				cloned := httpTransport.Clone()
				cloned.Proxy = http.ProxyURL(proxyURL)
				transport = cloned
			}
		}
		return assetDomainProbeStatusTransport{base: transport}
	}
	client := retryablehttp.NewClient(options)
	maxRedirects := defaultInt(request.MaxRedirects, 10)
	redirectPolicy := func(req *http.Request, via []*http.Request) error {
		if request.DisableRedirects {
			return http.ErrUseLastResponse
		}
		if maxRedirects >= 0 && len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}
	client.HTTPClient.CheckRedirect = redirectPolicy
	client.HTTPClient2.CheckRedirect = redirectPolicy
	return client
}

func doAssetDomainWappalyzerRequest(ctx context.Context, client *retryablehttp.Client, targetURL string, state *scanruntime.State) (*assetDomainProbeHTTPResponse, error) {
	if client == nil {
		client = retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	}
	recorder := &assetDomainProbeStatusRecorder{}
	requestCtx := context.WithValue(ctx, assetDomainProbeStatusRecorderKey{}, recorder)
	if state != nil {
		requestCtx = context.WithValue(requestCtx, assetDomainProbeStatsStateKey{}, state)
	}
	req, err := retryablehttp.NewRequestWithContext(requestCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	userAgent := useragent.PickRandom()
	req.Header.Set("User-Agent", userAgent.Raw)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	firstStatusCode := int(recorder.firstStatusCode.Load())
	if firstStatusCode <= 0 {
		firstStatusCode = resp.StatusCode
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, assetDomainWappalyzerMaxBody))
	if err != nil {
		return nil, err
	}
	return &assetDomainProbeHTTPResponse{
		Input:           finalAssetDomainResponseURL(resp, targetURL),
		StatusCode:      resp.StatusCode,
		FirstStatusCode: firstStatusCode,
		Headers:         resp.Header,
		Data:            data,
		Raw:             dumpAssetDomainResponse(resp, data),
		Request:         dumpAssetDomainRequest(resp.Request),
	}, nil
}

func (s *scanTaskService) runAssetDomainFingerprintTemplates(ctx context.Context, request dto.CreateScanTaskRequest, fingerprintTargets []assetDomainFingerprintTarget, taskDir string, state *scanruntime.State) ([]repository.AssetDomainServiceAssetObservation, error) {
	fingerprintTargets = uniqueAssetDomainFingerprintTargets(fingerprintTargets)
	if len(fingerprintTargets) == 0 || s.assetDomainRepository == nil {
		return nil, nil
	}

	targetsFile := filepath.Join(taskDir, "asset-domain-fingerprint-targets.txt")
	targetInputs := make([]string, 0, len(fingerprintTargets))
	for _, target := range fingerprintTargets {
		targetInputs = append(targetInputs, target.Input)
	}
	if err := os.WriteFile(targetsFile, []byte(strings.Join(targetInputs, "\n")+"\n"), 0o644); err != nil {
		return nil, err
	}

	executable, baseArgs := resolveManScanCommand(s.rootDir)
	args := append(baseArgs, buildAssetDomainFingerprintTemplateCLIArgs(request, taskDir, targetsFile)...)
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = s.rootDir
	prepareTaskCommand(cmd)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	queue := newAssetDomainServiceAssetQueueWithResolver(s, state, newAssetDomainFingerprintTargetResolver(fingerprintTargets))
	if queue == nil {
		return nil, nil
	}
	statsTracker := &assetDomainFingerprintTemplateStatsTracker{}

	if err := cmd.Start(); err != nil {
		queue.CloseAndWait()
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		streamAssetDomainFingerprintTemplateResults(stdoutPipe, queue, state, statsTracker)
	}()
	go func() {
		defer wg.Done()
		streamAssetDomainFingerprintTemplateStats(stderrPipe, state, statsTracker)
	}()

	waitErr := cmd.Wait()
	wg.Wait()
	queue.CloseAndWait()
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil, context.Canceled
	}
	return queue.Observations(), waitErr
}

func buildAssetDomainFingerprintTemplateCLIArgs(request dto.CreateScanTaskRequest, taskDir, targetsFile string) []string {
	args := []string{
		"-l", targetsFile,
		"-j",
		"-or",
		"-stats-json",
		"-stats",
		"-nc",
		"--tags", "tech,detect,favicon",
	}

	appendBool := func(enabled bool, flag string) {
		if enabled {
			args = append(args, flag)
		}
	}
	appendInt := func(value int, flag string) {
		if value > 0 {
			args = append(args, flag, strconv.Itoa(value))
		}
	}
	appendFlag := func(flag string, values ...string) {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value != "" {
				args = append(args, flag, value)
			}
		}
	}

	appendBool(request.ScanAllIPs, "-sa")
	appendBool(request.NoInteractsh, "-no-interactsh")
	appendBool(request.FollowRedirects, "-fr")
	appendBool(request.FollowHostRedirects, "-fhr")
	appendBool(request.DisableRedirects, "-dr")
	appendBool(request.ForceAttemptHTTP2, "-fh2")
	appendBool(request.TLSImpersonate, "-tlsi")
	appendBool(request.NoHostErrors, "-nmhe")
	appendBool(request.Headless, "--headless")
	appendBool(request.UseInstalledChrome, "-sc")
	appendBool(request.ProxyInternal, "-pi")

	appendInt(defaultInt(request.RateLimit, 150), "-rl")
	if duration := defaultInt64(request.RateLimitDuration, 1000); duration > 0 {
		args = append(args, "-rld", fmt.Sprintf("%dms", duration))
	}
	appendInt(defaultInt(request.BulkSize, 25), "-bs")
	appendInt(defaultInt(request.TemplateThreads, 25), "-c")
	appendInt(defaultInt(request.HeadlessBulkSize, 10), "-hbs")
	appendInt(defaultInt(request.HeadlessTemplateThreads, 10), "-headc")
	appendInt(defaultInt(request.JSConcurrency, 120), "-jsc")
	appendInt(defaultInt(request.PayloadConcurrency, 25), "-pc")
	appendInt(defaultInt(request.Timeout, 10), "--timeout")
	appendInt(defaultInt(request.Retries, 1), "--retries")
	appendInt(defaultInt(request.MaxHostError, 30), "-mhe")
	appendInt(defaultInt(request.PageTimeout, 20), "--page-timeout")

	if values := cleanStringSlice(request.ExcludeTargets); len(values) > 0 {
		args = append(args, "-eh", strings.Join(values, ","))
	}
	if values := cleanStringSlice(request.IPVersion); len(values) > 0 {
		args = append(args, "-iv", strings.Join(values, ","))
	}
	for _, header := range cleanStringSlice(request.CustomHeaders) {
		args = append(args, "-H", header)
	}
	for _, variable := range cleanStringSlice(request.Vars) {
		args = append(args, "-V", variable)
	}
	appendFlag("--sni", request.SNI)
	appendFlag("-sip", request.SourceIP)
	appendFlag("-ss", firstNonEmpty(request.ScanStrategy, "auto"))
	for _, item := range cleanStringSlice(request.HeadlessOptionalArguments) {
		args = append(args, "-ho", item)
	}
	appendFlag("-cdpe", request.CDPEndpoint)
	for _, proxy := range cleanStringSlice(request.Proxy) {
		args = append(args, "-p", proxy)
	}
	args = append(args, "-elog", filepath.Join(taskDir, "asset-domain-fingerprint-error.log"))
	return args
}

type assetDomainFingerprintTemplateStatsPayload struct {
	Requests       string `json:"requests"`
	ActualRequests string `json:"actual_requests"`
	Total          string `json:"total"`
	TotalKnown     string `json:"total_known"`
}

type assetDomainFingerprintTemplateStatsTracker struct {
	mu                 sync.Mutex
	lastRequests       int64
	lastActualRequests int64
	lastTotal          int64
}

func (t *assetDomainFingerprintTemplateStatsTracker) Handle(line string, state *scanruntime.State) bool {
	if state == nil || !strings.HasPrefix(line, "{") {
		return false
	}

	var payload assetDomainFingerprintTemplateStatsPayload
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return false
	}
	if payload.Requests == "" && payload.ActualRequests == "" && payload.Total == "" && payload.TotalKnown == "" {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	requests := scanruntime.ParseInt64(payload.Requests)
	actualRequests := scanruntime.ParseInt64(payload.ActualRequests)
	if actualRequests == 0 && payload.ActualRequests == "" {
		actualRequests = requests
	}

	requestDelta := requests - t.lastRequests
	if requestDelta < 0 {
		requestDelta = requests
	}
	actualDelta := actualRequests - t.lastActualRequests
	if actualDelta < 0 {
		actualDelta = actualRequests
	}

	totalDelta := int64(0)
	totalKnown := strings.EqualFold(strings.TrimSpace(payload.TotalKnown), "1") || strings.EqualFold(strings.TrimSpace(payload.TotalKnown), "true")
	if payload.TotalKnown == "" {
		totalKnown = payload.Total != ""
	}
	if totalKnown {
		total := scanruntime.ParseInt64(payload.Total)
		totalDelta = total - t.lastTotal
		if totalDelta < 0 {
			totalDelta = total
		}
		t.lastTotal = total
	}
	t.lastRequests = requests
	t.lastActualRequests = actualRequests

	state.AddRequestStats(totalDelta, actualDelta, requestDelta, "扫描前域名资产存活 & 指纹探测进度更新")
	return true
}

func streamAssetDomainFingerprintTemplateResults(reader io.Reader, queue *assetDomainServiceAssetQueue, state *scanruntime.State, statsTracker *assetDomainFingerprintTemplateStatsTracker) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	if statsTracker == nil {
		statsTracker = &assetDomainFingerprintTemplateStatsTracker{}
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if statsTracker.Handle(line, state) {
			continue
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			continue
		}
		queue.Enqueue(assetDomainServiceAssetResultEvent{payload: payload})
	}
}

func streamAssetDomainFingerprintTemplateStats(reader io.Reader, state *scanruntime.State, statsTracker *assetDomainFingerprintTemplateStatsTracker) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	if statsTracker == nil {
		statsTracker = &assetDomainFingerprintTemplateStatsTracker{}
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		statsTracker.Handle(line, state)
	}
}

func assetDomainWappalyzerComponents(wappalyzerClient *wappalyzer.Wappalyze, domain string, resp *assetDomainProbeHTTPResponse) []repository.AssetDomainServiceAssetObservation {
	if wappalyzerClient == nil || resp == nil {
		return nil
	}
	fingerprints := wappalyzerClient.Fingerprint(resp.Headers, resp.Data)
	components := make([]repository.AssetDomainServiceAssetObservation, 0, len(fingerprints))
	for value := range fingerprints {
		appName, appVersion := splitAssetDomainComponentVersion(value)
		appName = normalizeAssetDomainComponentName(appName)
		if appName == "" {
			continue
		}
		components = append(components, repository.AssetDomainServiceAssetObservation{
			Domain:     domain,
			AppName:    appName,
			AppVersion: strings.TrimSpace(appVersion),
		})
	}
	return uniqueAssetDomainServiceAssetObservations(components)
}

func splitAssetDomainComponentVersion(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	appName, appVersion, ok := strings.Cut(value, ":")
	if !ok {
		return value, ""
	}
	return strings.TrimSpace(appName), strings.TrimSpace(appVersion)
}

func normalizeAssetDomainComponentName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.ToLower(value)
}

func uniqueAssetDomainServiceAssetObservations(values []repository.AssetDomainServiceAssetObservation) []repository.AssetDomainServiceAssetObservation {
	result := make([]repository.AssetDomainServiceAssetObservation, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.Domain = strings.TrimSpace(value.Domain)
		value.AppName = normalizeAssetDomainComponentName(value.AppName)
		value.AppVersion = strings.TrimSpace(value.AppVersion)
		if value.Domain == "" || value.AppName == "" {
			continue
		}
		key := value.Domain + "\x00" + value.AppName
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueAssetDomainFingerprintCacheEntries(values []assetDomainFingerprintCacheEntry) []assetDomainFingerprintCacheEntry {
	result := make([]assetDomainFingerprintCacheEntry, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.Target = strings.TrimSpace(value.Target)
		value.Domain = strings.TrimSpace(value.Domain)
		value.Components = uniqueAssetDomainFingerprintCacheComponents(value.Components)
		if value.Domain == "" {
			continue
		}
		if _, ok := seen[value.Domain]; ok {
			continue
		}
		seen[value.Domain] = struct{}{}
		result = append(result, value)
	}
	return result
}

func assetDomainFingerprintCacheComponents(values []repository.AssetDomainServiceAssetObservation) []assetDomainFingerprintCacheComponent {
	components := make([]assetDomainFingerprintCacheComponent, 0, len(values))
	for _, value := range uniqueAssetDomainServiceAssetObservations(values) {
		components = append(components, assetDomainFingerprintCacheComponent{
			Domain:     value.Domain,
			AppName:    value.AppName,
			AppVersion: value.AppVersion,
		})
	}
	return components
}

func uniqueAssetDomainFingerprintCacheComponents(values []assetDomainFingerprintCacheComponent) []assetDomainFingerprintCacheComponent {
	result := make([]assetDomainFingerprintCacheComponent, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.Domain = strings.TrimSpace(value.Domain)
		value.AppName = normalizeAssetDomainComponentName(value.AppName)
		value.AppVersion = strings.TrimSpace(value.AppVersion)
		if value.Domain == "" || value.AppName == "" {
			continue
		}
		key := value.Domain + "\x00" + value.AppName
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueAssetDomainFingerprintTargets(values []assetDomainFingerprintTarget) []assetDomainFingerprintTarget {
	result := make([]assetDomainFingerprintTarget, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.Input = strings.TrimSpace(value.Input)
		value.Domain = strings.TrimSpace(value.Domain)
		value.FinalURL = strings.TrimSpace(value.FinalURL)
		if value.Input == "" || value.Domain == "" {
			continue
		}
		key := value.Input + "\x00" + value.Domain
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueNonEmptyStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func writeAssetDomainFingerprintCache(path string, fingerprints []assetDomainFingerprintCacheEntry) error {
	path = strings.TrimSpace(path)
	if path == "" || len(fingerprints) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(fingerprints)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
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

func firstAssetDomainHTTPStatusCode(resp *assetDomainProbeHTTPResponse) uint {
	if resp == nil {
		return 0
	}
	if resp.FirstStatusCode > 0 {
		return uint(resp.FirstStatusCode)
	}
	if resp.StatusCode > 0 {
		return uint(resp.StatusCode)
	}
	return 0
}

func assetDomainResponseTitle(resp *assetDomainProbeHTTPResponse) string {
	if resp == nil {
		return ""
	}
	matches := assetDomainTitlePattern.FindSubmatch(resp.Data)
	if len(matches) < 2 {
		return ""
	}
	title := html.UnescapeString(string(bytes.TrimSpace(matches[1])))
	return strings.Join(strings.Fields(title), " ")
}

func finalAssetDomainRequest(resp *assetDomainProbeHTTPResponse) string {
	if resp == nil {
		return ""
	}
	return resp.Request
}

func finalAssetDomainResponseURL(resp *http.Response, fallback string) string {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return fallback
	}
	if value := strings.TrimSpace(resp.Request.URL.String()); value != "" {
		return value
	}
	return fallback
}

func dumpAssetDomainRequest(req *http.Request) string {
	if req == nil {
		return ""
	}
	data, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		return strings.TrimSpace(req.Method + " " + req.URL.String())
	}
	return string(data)
}

func dumpAssetDomainResponse(resp *http.Response, data []byte) string {
	if resp == nil {
		return ""
	}
	header, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return string(data)
	}
	return string(header) + string(data)
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
