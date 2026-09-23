package service

import (
	"context"
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

type assetDomainServiceAssetResultEvent struct {
	payload map[string]interface{}
}

type assetDomainServiceAssetQueue struct {
	service      *scanTaskService
	events       chan assetDomainServiceAssetResultEvent
	once         sync.Once
	wg           sync.WaitGroup
	observations []repository.AssetDomainServiceAssetObservation
	mu           sync.Mutex
}

func newAssetDomainServiceAssetQueue(service *scanTaskService) *assetDomainServiceAssetQueue {
	if service == nil || service.assetDomainRepository == nil {
		return nil
	}

	queue := &assetDomainServiceAssetQueue{
		service: service,
		events:  make(chan assetDomainServiceAssetResultEvent, assetDomainServiceAssetQueueBufferSize),
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
	observations, err := q.service.buildAssetDomainServiceAssetsFromPayload(context.Background(), event.payload)
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
		appVersion = strings.TrimSpace(appVersion)
		if appName != "" && appVersion != "" {
			if _, ok := componentSet[appName]; ok {
				versions[appName] = appVersion
			}
			continue
		}
		if len(componentNames) == 1 {
			value := strings.TrimSpace(extracted)
			if value != "" {
				versions[componentNames[0]] = value
			}
		}
	}
	return versions
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
