package service

import (
	"context"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/scanruntime"
	"ManScan/server/internal/repository"
)

const (
	assetDomainServiceAssetQueueBufferSize   = 4096
	assetDomainServiceAssetQueueBatchSize    = 100
	assetDomainServiceAssetQueueFlushTimeout = time.Second
)

var assetDomainComponentVersionTokenPattern = regexp.MustCompile(`(?i)^v?\d+(?:[._-]\d+)*(?:[-+._~]?[0-9a-z]+)*$`)

type assetDomainServiceAssetResultEvent struct {
	payload map[string]interface{}
}

type assetDomainServiceAssetQueue struct {
	service      *scanTaskService
	state        *scanruntime.State
	resolver     *assetDomainFingerprintTargetResolver
	events       chan assetDomainServiceAssetResultEvent
	once         sync.Once
	wg           sync.WaitGroup
	observations []repository.AssetDomainServiceAssetObservation
	mu           sync.Mutex
	resolverMu   sync.RWMutex
}

func newAssetDomainServiceAssetQueue(service *scanTaskService, states ...*scanruntime.State) *assetDomainServiceAssetQueue {
	var state *scanruntime.State
	if len(states) > 0 {
		state = states[0]
	}
	return newAssetDomainServiceAssetQueueWithResolver(service, state, nil)
}

func newAssetDomainServiceAssetQueueWithResolver(service *scanTaskService, state *scanruntime.State, resolver *assetDomainFingerprintTargetResolver) *assetDomainServiceAssetQueue {
	if service == nil || service.assetDomainRepository == nil {
		return nil
	}

	queue := &assetDomainServiceAssetQueue{
		service:  service,
		state:    state,
		resolver: resolver,
		events:   make(chan assetDomainServiceAssetResultEvent, assetDomainServiceAssetQueueBufferSize),
	}
	queue.wg.Add(1)
	go queue.runWorker()
	return queue
}

func (q *assetDomainServiceAssetQueue) Enqueue(event assetDomainServiceAssetResultEvent) {
	if q == nil {
		return
	}
	q.events <- event
}

func (q *assetDomainServiceAssetQueue) CloseAndWait() {
	if q == nil {
		return
	}
	q.once.Do(func() {
		close(q.events)
	})
	q.wg.Wait()
}

func (q *assetDomainServiceAssetQueue) SetTargetResolver(resolver *assetDomainFingerprintTargetResolver) {
	if q == nil {
		return
	}
	q.resolverMu.Lock()
	q.resolver = resolver
	q.resolverMu.Unlock()
}

func (q *assetDomainServiceAssetQueue) Observations() []repository.AssetDomainServiceAssetObservation {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	observations := make([]repository.AssetDomainServiceAssetObservation, 0, len(q.observations))
	observations = append(observations, q.observations...)
	return uniqueAssetDomainServiceAssetObservations(observations)
}

func (q *assetDomainServiceAssetQueue) runWorker() {
	defer q.wg.Done()

	ticker := time.NewTicker(assetDomainServiceAssetQueueFlushTimeout)
	defer ticker.Stop()

	batch := make([]repository.AssetDomainServiceAssetObservation, 0, assetDomainServiceAssetQueueBatchSize)
	for {
		select {
		case event, ok := <-q.events:
			if !ok {
				q.flush(batch)
				return
			}
			observations := q.build(event)
			q.record(observations)
			recordAssetDomainFingerprintObservations(q.state, observations)
			batch = append(batch, observations...)
			if len(batch) >= assetDomainServiceAssetQueueBatchSize {
				q.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) == 0 {
				continue
			}
			q.flush(batch)
			batch = batch[:0]
		}
	}
}

func (q *assetDomainServiceAssetQueue) build(event assetDomainServiceAssetResultEvent) []repository.AssetDomainServiceAssetObservation {
	q.resolverMu.RLock()
	resolver := q.resolver
	q.resolverMu.RUnlock()
	observations, err := q.service.buildAssetDomainServiceAssetsFromPayloadWithResolver(context.Background(), event.payload, resolver)
	if err != nil {
		if q.service.logger != nil {
			q.service.logger.Error("build asset domain service assets from scan result failed", "error", err)
		}
		return nil
	}
	return observations
}

func (q *assetDomainServiceAssetQueue) record(observations []repository.AssetDomainServiceAssetObservation) {
	if q == nil || len(observations) == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	q.observations = append(q.observations, observations...)
}

func (q *assetDomainServiceAssetQueue) flush(batch []repository.AssetDomainServiceAssetObservation) {
	batch = uniqueAssetDomainServiceAssetObservations(batch)
	if len(batch) == 0 {
		return
	}

	if err := q.service.assetDomainRepository.SyncServiceAssets(context.Background(), batch, nil, time.Now()); err != nil && q.service.logger != nil {
		q.service.logger.Error("batch sync asset domain service assets failed", "count", len(batch), "error", err)
	}
}

func (s *scanTaskService) buildAssetDomainServiceAssetsFromPayload(ctx context.Context, payload map[string]interface{}) ([]repository.AssetDomainServiceAssetObservation, error) {
	return s.buildAssetDomainServiceAssetsFromPayloadWithResolver(ctx, payload, nil)
}

func (s *scanTaskService) buildAssetDomainServiceAssetsFromPayloadWithResolver(ctx context.Context, payload map[string]interface{}, resolver *assetDomainFingerprintTargetResolver) ([]repository.AssetDomainServiceAssetObservation, error) {
	if len(payload) == 0 {
		return nil, nil
	}

	templateID := strings.TrimSpace(scanruntime.AsString(payload["template-id"]))
	info := payloadInfo(payload)
	templateDetail, err := s.findTemplateDetail(ctx, templateID)
	if err != nil {
		return nil, err
	}

	payloadTags := interfaceStringSlice(info["tags"])
	templateTags := templateDetailStrings(templateDetail, func(detail *dto.TemplateDetail) []string { return detail.Tags })
	tags := mergeStringSlices(templateTags, payloadTags)
	if !scanruntime.HasFingerprintTag(tags) {
		return nil, nil
	}

	matchedAt := firstNonEmpty(
		scanruntime.AsString(payload["matched-at"]),
		scanruntime.AsString(payload["url"]),
		scanruntime.AsString(payload["host"]),
	)
	domain := vulnerabilityAssetEndpoint(parseVulnerabilityAsset(payload, matchedAt))
	if resolver != nil {
		if originalDomain := resolver.Resolve(payload); originalDomain != "" {
			domain = originalDomain
		}
	}
	if domain == "" {
		return nil, nil
	}

	componentNames := assetDomainFingerprintComponentNames(payload, templateID, info, tags)
	components := make([]repository.AssetDomainServiceAssetObservation, 0, len(componentNames))
	versionsByName := assetDomainFingerprintExtractedVersions(payload, componentNames)
	for _, componentName := range componentNames {
		components = append(components, repository.AssetDomainServiceAssetObservation{
			Domain:     domain,
			AppName:    componentName,
			AppVersion: versionsByName[componentName],
		})
	}
	return uniqueAssetDomainServiceAssetObservations(components), nil
}

type assetDomainFingerprintTargetResolver struct {
	endpointToDomain map[string]string
	hostToDomain     map[string]string
}

func newAssetDomainFingerprintTargetResolver(targets []assetDomainFingerprintTarget) *assetDomainFingerprintTargetResolver {
	resolver := &assetDomainFingerprintTargetResolver{
		endpointToDomain: make(map[string]string),
		hostToDomain:     make(map[string]string),
	}
	for _, target := range targets {
		domain := strings.TrimSpace(target.Domain)
		if domain == "" {
			continue
		}
		resolver.add(target.Input, domain)
		resolver.add(target.FinalURL, domain)
		resolver.add(target.Domain, domain)
	}
	return resolver
}

func (r *assetDomainFingerprintTargetResolver) add(value, domain string) {
	endpoint, host := assetDomainFingerprintValueKeys(value)
	if endpoint != "" {
		addUniqueAssetDomainFingerprintAlias(r.endpointToDomain, endpoint, domain)
	}
	if host != "" {
		addUniqueAssetDomainFingerprintAlias(r.hostToDomain, host, domain)
	}
}

func (r *assetDomainFingerprintTargetResolver) Resolve(payload map[string]interface{}) string {
	if r == nil {
		return ""
	}
	for _, key := range []string{"input", "matched-at", "url", "host"} {
		endpoint, host := assetDomainFingerprintValueKeys(scanruntime.AsString(payload[key]))
		if endpoint != "" {
			if domain := r.endpointToDomain[endpoint]; domain != "" {
				return domain
			}
		}
		if host != "" {
			if domain := r.hostToDomain[host]; domain != "" {
				return domain
			}
		}
	}
	return ""
}

func assetDomainFingerprintValueKeys(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	parsed, ok := parseEndpoint(value)
	if !ok {
		value = strings.ToLower(value)
		return value, value
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return "", ""
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
		return host, host
	}
	return net.JoinHostPort(host, port), host
}

func addUniqueAssetDomainFingerprintAlias(aliases map[string]string, key, domain string) {
	if key == "" {
		return
	}
	if current, ok := aliases[key]; ok && current != domain {
		aliases[key] = ""
		return
	}
	aliases[key] = domain
}

func assetDomainFingerprintComponentNames(payload map[string]interface{}, templateID string, info map[string]interface{}, tags []string) []string {
	names := make([]string, 0)
	if name := normalizeAssetDomainComponentName(scanruntime.AsString(payload["matcher-name"])); name != "" {
		names = append(names, name)
	}

	templateID = strings.ToLower(strings.TrimSpace(templateID))
	infoName := strings.ToLower(strings.TrimSpace(scanruntime.AsString(info["name"])))
	for _, tag := range tags {
		tag = normalizeAssetDomainComponentName(tag)
		if tag == "" || scanruntime.HasFingerprintTag([]string{tag}) {
			continue
		}
		if !strings.Contains(templateID, tag) && !strings.Contains(infoName, tag) {
			continue
		}
		names = append(names, tag)
	}

	for _, extracted := range interfaceStringSlice(payload["extracted-results"]) {
		appName, _ := splitAssetDomainComponentVersion(extracted)
		appName = normalizeAssetDomainComponentName(appName)
		if appName != "" && appName != normalizeAssetDomainComponentName(extracted) {
			names = append(names, appName)
		}
	}
	return uniqueComponentNames(names)
}

func assetDomainFingerprintExtractedVersions(payload map[string]interface{}, componentNames []string) map[string]string {
	versions := make(map[string]string)
	extractedResults := interfaceStringSlice(payload["extracted-results"])
	if len(extractedResults) == 0 {
		return versions
	}

	componentSet := make(map[string]struct{}, len(componentNames))
	for _, name := range componentNames {
		componentSet[name] = struct{}{}
	}
	for _, extracted := range extractedResults {
		appName, appVersion := splitAssetDomainComponentVersion(extracted)
		appName = normalizeAssetDomainComponentName(appName)
		appVersion = normalizeAssetDomainComponentVersion(appVersion)
		if appName != "" && appVersion != "" {
			if _, ok := componentSet[appName]; ok {
				versions[appName] = appVersion
			}
			continue
		}
		if len(componentNames) == 1 {
			version := normalizeAssetDomainComponentVersion(extracted)
			if version != "" {
				versions[componentNames[0]] = version
			}
		}
	}
	return versions
}

func normalizeAssetDomainComponentVersion(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if value == "" {
		return ""
	}
	if assetDomainComponentVersionTokenPattern.MatchString(value) {
		return value
	}
	for _, separator := range []string{"/", " "} {
		if index := strings.LastIndex(value, separator); index >= 0 && index+1 < len(value) {
			candidate := strings.Trim(strings.TrimSpace(value[index+1:]), `"'`)
			if assetDomainComponentVersionTokenPattern.MatchString(candidate) {
				return candidate
			}
		}
	}
	return ""
}

func uniqueComponentNames(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = normalizeAssetDomainComponentName(value)
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
