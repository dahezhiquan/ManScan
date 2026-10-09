package automaticscan

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"ManScan/pkg/catalog/config"
	"ManScan/pkg/catalog/loader"
	"ManScan/pkg/core"
	"ManScan/pkg/input/provider"
	"ManScan/pkg/output"
	"ManScan/pkg/progress"
	"ManScan/pkg/protocols"
	"ManScan/pkg/protocols/common/assetdomainfingerprint"
	"ManScan/pkg/protocols/common/contextargs"
	"ManScan/pkg/protocols/common/helpers/writer"
	"ManScan/pkg/protocols/http/httpclientpool"
	"ManScan/pkg/scan"
	"ManScan/pkg/templates"
	templateTypes "ManScan/pkg/templates/types"
	"ManScan/pkg/utils/yaml"
	"github.com/logrusorgru/aurora/v4"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/useragent"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
	unitutils "github.com/projectdiscovery/utils/unit"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const (
	mappingFilename = "wappalyzer-mapping.yml"
	maxDefaultBody  = 4 * unitutils.Mega
)

// Options contains configuration options for automatic scan service
type Options struct {
	ExecuterOpts *protocols.ExecutorOptions
	Store        *loader.Store
	Engine       *core.Engine
	Target       provider.InputProvider
}

// Service is a service for automatic scan execution
type Service struct {
	opts               *protocols.ExecutorOptions
	store              *loader.Store
	engine             *core.Engine
	target             provider.InputProvider
	wappalyzer         *wappalyzer.Wappalyze
	httpclient         *retryablehttp.Client
	templateDirs       []string // root Template Directories
	technologyMappings map[string]string
	techTemplates      []*templates.Template
	techTemplateStats  templateLoadStats
	fingerprintCache   *assetdomainfingerprint.Cache
	totalGate          *totalGate
	ServiceOpts        Options
	hasResults         *atomic.Bool
}

type mappedTarget struct {
	input                      *contextargs.MetaInput
	finalTemplates             []*templates.Template
	preClusterRequests         int64
	usedCachedWappalyzer       bool
	skipHTTPDetectionTemplates bool
}

type totalGate struct {
	progress progress.Progress
	mu       sync.Mutex
	known    bool
	pending  int64
}

func newTotalGate(progressClient progress.Progress) *totalGate {
	return &totalGate{progress: progressClient}
}

func (g *totalGate) Add(delta int64) {
	if g == nil || delta <= 0 {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.known {
		g.pending += delta
		return
	}
	if g.progress != nil {
		g.progress.AddToTotal(delta)
	}
}

func (g *totalGate) Publish(total, preClusterTotal int64) {
	if g == nil {
		return
	}

	g.mu.Lock()
	total += g.pending
	preClusterTotal += g.pending
	g.pending = 0
	g.known = true
	if g.progress != nil {
		if setter, ok := g.progress.(interface{ SetTotal(int64) }); ok {
			setter.SetTotal(total)
		} else {
			g.progress.AddToTotal(total)
		}
		if setter, ok := g.progress.(interface{ SetPreClusterTotal(int64) }); ok {
			setter.SetPreClusterTotal(preClusterTotal)
		}
	}
	g.mu.Unlock()
}

// phaseProgress prevents an inner engine from resetting the outer scan
// counters while still forwarding every request and match event.
type phaseProgress struct {
	progress.Progress
	totalGate *totalGate
}

func (p *phaseProgress) Init(hostCount int64, rulesCount int, requestCount int64) {}

func (p *phaseProgress) SetTotal(total int64) {
	// The outer automatic-scan phase publishes one aggregate estimate after
	// every target has completed fingerprint mapping. Inner engines must not
	// publish a target-local estimate before that point.
}

func (p *phaseProgress) AddToTotal(delta int64) {
	if p.totalGate != nil {
		p.totalGate.Add(delta)
		return
	}
	if p.Progress != nil {
		p.Progress.AddToTotal(delta)
	}
}

func (p *phaseProgress) IncrementRequests() {
	if p.Progress != nil {
		p.Progress.IncrementRequests()
	}
}

func (p *phaseProgress) IncrementActualRequests() {
	if p.Progress != nil {
		p.Progress.IncrementActualRequests()
	}
}

func (p *phaseProgress) SetRequests(count uint64) {
	if p.Progress != nil {
		p.Progress.SetRequests(count)
	}
}

func (p *phaseProgress) IncrementSkippedRequests(count int64) {
	if p.Progress != nil {
		progress.IncrementSkippedRequests(p.Progress, count)
	}
}

func (p *phaseProgress) IncrementMatched() {
	if p.Progress != nil {
		p.Progress.IncrementMatched()
	}
}

func (p *phaseProgress) IncrementErrorsBy(count int64) {
	if p.Progress != nil {
		p.Progress.IncrementErrorsBy(count)
	}
}

func (p *phaseProgress) IncrementFailedRequestsBy(count int64) {
	if p.Progress != nil {
		p.Progress.IncrementFailedRequestsBy(count)
	}
}

// New takes options and returns a new automatic scan service
func New(opts Options) (*Service, error) {
	wappalyzer, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}

	// load extra mapping from nuclei-templates for normalization
	var mappingData map[string]string
	mappingFile := filepath.Join(config.DefaultConfig.GetTemplateDir(), mappingFilename)
	if file, err := os.Open(mappingFile); err == nil {
		_ = yaml.NewDecoder(file).Decode(&mappingData)
		_ = file.Close()
	}
	if opts.ExecuterOpts.Options.Verbose {
		gologger.Verbose().Msgf("Normalized mapping (%d): %v\n", len(mappingData), mappingData)
	}

	// get template directories
	templateDirs, err := getTemplateDirs(opts)
	if err != nil {
		return nil, err
	}

	// load tech detect templates
	techDetectTemplates, techTemplateStats, err := loadTemplatesWithTagsWithStats(opts, templateDirs, []string{"tech", "detect", "favicon"}, true, false)
	if err != nil {
		return nil, err
	}

	httpclient, err := httpclientpool.Get(opts.ExecuterOpts.Options, &httpclientpool.Configuration{
		DisableCookie: true,
	}, "")
	if err != nil {
		return nil, errors.Wrap(err, "could not get http client")
	}
	return &Service{
		opts:               opts.ExecuterOpts,
		store:              opts.Store,
		engine:             opts.Engine,
		target:             opts.Target,
		wappalyzer:         wappalyzer,
		templateDirs:       templateDirs, // fix this
		httpclient:         httpclient,
		technologyMappings: mappingData,
		techTemplates:      techDetectTemplates,
		techTemplateStats:  techTemplateStats,
		fingerprintCache:   firstNonNilFingerprintCache(opts.ExecuterOpts.AssetDomainFingerprintCache, assetdomainfingerprint.LoadFromEnv()),
		ServiceOpts:        opts,
		hasResults:         &atomic.Bool{},
	}, nil
}

// Close closes the service
func (s *Service) Close() bool {
	return s.hasResults.Load()
}

// Execute automatic scan on each target with -bs host concurrency
func (s *Service) Execute() error {
	gologger.Info().Msgf("Executing Automatic scan on %d target[s]", s.target.Count())
	s.totalGate = newTotalGate(s.opts.Progress)

	// Run each target as a small pipeline: once its fingerprint mapping is
	// ready, start vulnerability templates immediately while other targets
	// continue fingerprinting. The aggregate estimate is published only after
	// all mappings are collected.
	mappingSG, err := syncutil.New(syncutil.WithSize(s.opts.Options.BulkSize))
	if err != nil {
		return err
	}
	scanSG, err := syncutil.New(syncutil.WithSize(s.opts.Options.BulkSize))
	if err != nil {
		return err
	}
	var scanLaunchWG sync.WaitGroup
	mappedTargets := make(chan mappedTarget, s.target.Count())
	s.target.Iterate(func(value *contextargs.MetaInput) bool {
		mappingSG.Add()
		go func(input *contextargs.MetaInput) {
			defer mappingSG.Done()
			target := s.mapTarget(input)
			mappedTargets <- target
			if len(target.finalTemplates) == 0 {
				return
			}

			scanLaunchWG.Add(1)
			go func() {
				scanSG.Add()
				scanLaunchWG.Done()
				defer scanSG.Done()
				s.executeMappedTemplates(target)
			}()
		}(value)
		return true
	})
	mappingSG.Wait()
	close(mappedTargets)

	var targets []mappedTarget
	for target := range mappedTargets {
		targets = append(targets, target)
	}

	s.setMappedRequestTotal(targets)
	scanLaunchWG.Wait()
	scanSG.Wait()
	return nil
}

func (s *Service) mapTarget(input *contextargs.MetaInput) mappedTarget {
	// get tags using wappalyzer
	tagsFromWappalyzer, usedCachedWappalyzer := s.getTagsUsingCachedWappalyzer(input)
	if !usedCachedWappalyzer {
		tagsFromWappalyzer = s.getTagsUsingWappalyzer(input)
	}
	// get tags using detection templates
	skipHTTPDetectionTemplates := s.cachedHTTPProbeFailed(input)
	tagsFromDetectTemplates, matched := s.getTagsUsingDetectionTemplates(input, skipHTTPDetectionTemplates)
	if matched > 0 {
		s.hasResults.Store(true)
	}

	// create combined final tags
	finalTags := []string{}
	for _, tags := range append(tagsFromWappalyzer, tagsFromDetectTemplates...) {
		if stringsutil.EqualFoldAny(tags, "tech", "waf", "favicon") {
			continue
		}
		finalTags = append(finalTags, tags)
	}
	finalTags = sliceutil.Dedupe(finalTags)

	gologger.Info().Msgf("Found %d tags and %d matches on detection templates on %v [wappalyzer: %d, detection: %d]\n", len(finalTags), matched, input.Input, len(tagsFromWappalyzer), len(tagsFromDetectTemplates))

	// also include any extra tags passed by user
	finalTags = append(finalTags, s.opts.Options.Tags...)
	finalTags = sliceutil.Dedupe(finalTags)
	finalTags = filterAutomaticScanExecutionTags(finalTags)

	s.opts.Logger.Info().Msgf("%s 已完成自动指纹识别：%s", input.Input, automaticFingerprintTagsMessage(finalTags))

	if len(finalTags) == 0 {
		gologger.Warning().Msgf("Skipping automatic scan since no vulnerability tags were found on %v\n", input.Input)
		return mappedTarget{input: input, usedCachedWappalyzer: usedCachedWappalyzer, skipHTTPDetectionTemplates: skipHTTPDetectionTemplates}
	}

	finalTemplates, loadStats, err := loadTemplatesWithTagsWithStats(s.ServiceOpts, s.templateDirs, finalTags, false, skipHTTPDetectionTemplates)
	if err != nil {
		gologger.Error().Msgf("%v Error loading templates: %s\n", input.Input, err)
		return mappedTarget{input: input, usedCachedWappalyzer: usedCachedWappalyzer, skipHTTPDetectionTemplates: skipHTTPDetectionTemplates}
	}
	s.opts.Logger.Info().Msgf("%s 已加载漏洞模版数量：%d", input.Input, len(finalTemplates))
	preClusterRequests := loadStats.PreClusterRequests
	if skipHTTPDetectionTemplates {
		preClusterRequests = loadStats.PreClusterNonHTTPRequests
	}
	return mappedTarget{
		input:                      input,
		finalTemplates:             finalTemplates,
		preClusterRequests:         preClusterRequests,
		usedCachedWappalyzer:       usedCachedWappalyzer,
		skipHTTPDetectionTemplates: skipHTTPDetectionTemplates,
	}
}

func (s *Service) setMappedRequestTotal(targets []mappedTarget) {
	if s.opts.Progress == nil {
		return
	}

	// Wappalyzer performs one direct request per target. Detection templates
	// and mapped vulnerability templates expose their compiled request counts.
	wappalyzerTargets := int64(s.target.Count())
	for _, target := range targets {
		if target.usedCachedWappalyzer {
			wappalyzerTargets--
		}
	}
	total := wappalyzerTargets
	preClusterTotal := wappalyzerTargets
	for _, target := range targets {
		for _, template := range s.techTemplates {
			if target.skipHTTPDetectionTemplates && isHTTPFingerprintTemplate(template) {
				continue
			}
			total += int64(template.TotalRequests)
		}
		if target.skipHTTPDetectionTemplates {
			preClusterTotal += s.techTemplateStats.PreClusterNonHTTPRequests
		} else {
			preClusterTotal += s.techTemplateStats.PreClusterRequests
		}
	}
	for _, target := range targets {
		for _, template := range target.finalTemplates {
			total += int64(template.TotalRequests)
		}
		preClusterTotal += target.preClusterRequests
	}
	s.totalGate.Publish(total, preClusterTotal)
	if setter, ok := s.opts.Progress.(interface{ SetTemplateCount(int64) }); ok {
		setter.SetTemplateCount(mappedTemplateCount(targets))
	}
}

func mappedTemplateCount(targets []mappedTarget) int64 {
	templateIDs := make(map[string]struct{})
	for _, target := range targets {
		for _, template := range target.finalTemplates {
			if template == nil {
				continue
			}
			templateID := strings.TrimSpace(template.ID)
			if templateID == "" {
				templateID = strings.TrimSpace(template.Path)
			}
			if templateID != "" {
				templateIDs[templateID] = struct{}{}
			}
		}
	}
	return int64(len(templateIDs))
}

func (s *Service) executeMappedTemplates(target mappedTarget) {
	gologger.Info().Msgf("Executing %d templates on %v", len(target.finalTemplates), target.input.Input)
	eng := core.New(s.opts.Options)
	execOptions := s.opts.Copy()
	execOptions.Progress = &phaseProgress{Progress: s.opts.Progress, totalGate: s.totalGate}
	eng.SetExecuterOptions(execOptions)

	tmp := eng.ExecuteScanWithOpts(context.Background(), target.finalTemplates, provider.NewSimpleInputProviderWithUrls(s.opts.Options.ExecutionId, target.input.Input), true)
	if tmp.Load() {
		s.hasResults.Store(true)
	}
}

func filterAutomaticScanExecutionTags(tags []string) []string {
	filtered := make([]string, 0, len(tags))
	for _, tag := range tags {
		if strings.EqualFold(tag, "detect") {
			continue
		}
		filtered = append(filtered, tag)
	}
	return filtered
}

func automaticFingerprintTagsMessage(tags []string) string {
	if len(tags) == 0 {
		return "未发现"
	}
	return strings.Join(tags, ", ")
}

func filterHTTPBasedTemplates(values []*templates.Template) []*templates.Template {
	filtered := make([]*templates.Template, 0, len(values))
	for _, template := range values {
		if isHTTPFingerprintTemplate(template) {
			continue
		}
		filtered = append(filtered, template)
	}
	return filtered
}

func firstNonNilFingerprintCache(values ...*assetdomainfingerprint.Cache) *assetdomainfingerprint.Cache {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

// getTagsUsingWappalyzer returns tags using wappalyzer by fingerprinting target
// and utilizing the mapping data
func (s *Service) getTagsUsingWappalyzer(input *contextargs.MetaInput) []string {
	req, err := retryablehttp.NewRequest(http.MethodGet, input.Input, nil)
	if err != nil {
		return nil
	}
	userAgent := useragent.PickRandom()
	req.Header.Set("User-Agent", userAgent.Raw)

	if s.opts.Progress != nil {
		s.opts.Progress.IncrementActualRequests()
	}
	resp, err := s.httpclient.Do(req)
	if err != nil {
		if s.opts.Progress != nil {
			s.opts.Progress.IncrementFailedRequestsBy(1)
		}
		return nil
	}
	if s.opts.Progress != nil {
		s.opts.Progress.IncrementRequests()
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDefaultBody))
	if err != nil {
		return nil
	}

	// fingerprint headers and body
	fingerprints := s.wappalyzer.Fingerprint(resp.Header, data)
	normalized := make(map[string]struct{})
	for k := range fingerprints {
		normalized[normalizeAppName(k)] = struct{}{}
	}
	gologger.Verbose().Msgf("Found %d fingerprints for %s\n", len(normalized), input.Input)

	// normalize fingerprints using mapping data
	for k := range normalized {
		// Replace values with mapping data
		if value, ok := s.technologyMappings[k]; ok {
			delete(normalized, k)
			normalized[value] = struct{}{}
		}
	}
	// more post processing
	items := make([]string, 0, len(normalized))
	for k := range normalized {
		if strings.Contains(k, " ") {
			parts := strings.Split(strings.ToLower(k), " ")
			items = append(items, parts...)
		} else {
			items = append(items, strings.ToLower(k))
		}
	}
	return sliceutil.Dedupe(items)
}

func (s *Service) getTagsUsingCachedWappalyzer(input *contextargs.MetaInput) ([]string, bool) {
	if s == nil || input == nil || s.fingerprintCache == nil {
		return nil, false
	}

	state, ok := s.fingerprintCache.Lookup(input.Input)
	if !ok {
		return nil, false
	}

	normalized := make(map[string]struct{})
	for _, component := range state.Components {
		appName := normalizeAppName(component.AppName)
		if appName == "" {
			continue
		}
		normalized[appName] = struct{}{}
	}
	for appName := range normalized {
		if value, ok := s.technologyMappings[appName]; ok {
			delete(normalized, appName)
			normalized[value] = struct{}{}
		}
	}

	items := make([]string, 0, len(normalized))
	for appName := range normalized {
		if strings.Contains(appName, " ") {
			items = append(items, strings.Split(strings.ToLower(appName), " ")...)
		} else {
			items = append(items, strings.ToLower(appName))
		}
	}
	return sliceutil.Dedupe(items), true
}

func (s *Service) cachedHTTPProbeFailed(input *contextargs.MetaInput) bool {
	if s == nil || input == nil || s.fingerprintCache == nil {
		return false
	}
	return s.fingerprintCache.HTTPProbeFailed(input.Input)
}

// getTagsUsingDetectionTemplates returns tags using detection templates
func (s *Service) getTagsUsingDetectionTemplates(input *contextargs.MetaInput, skipHTTPTemplates ...bool) ([]string, int) {
	ctx := context.Background()

	ctxArgs := contextargs.NewWithInput(ctx, input.Input)
	skipHTTP := len(skipHTTPTemplates) > 0 && skipHTTPTemplates[0]

	// execute tech detection templates on target
	tags := map[string]struct{}{}
	m := &sync.Mutex{}
	sg, _ := syncutil.New(syncutil.WithSize(s.opts.Options.TemplateThreads))
	counter := atomic.Uint32{}

	for _, t := range s.techTemplates {
		if skipHTTP && isHTTPFingerprintTemplate(t) {
			continue
		}
		sg.Add()
		go func(template *templates.Template) {
			defer sg.Done()
			ctx := scan.NewScanContext(ctx, ctxArgs)
			ctx.OnResult = func(event *output.InternalWrappedEvent) {
				if event == nil {
					return
				}
				if event.HasOperatorResult() {
					// match found
					// find unique tags
					m.Lock()
					for _, v := range event.Results {
						if v.MatcherName != "" {
							tags[v.MatcherName] = struct{}{}
						}
						for _, tag := range v.Info.Tags.ToSlice() {
							// we shouldn't add all tags since tags also contain protocol type tags
							// and are not just limited to products or technologies
							// ex:   tags: js,mssql,detect,network

							// A good trick for this is check if tag is present in template-id
							if !strings.Contains(template.ID, tag) && !strings.Contains(strings.ToLower(template.Info.Name), tag) {
								// unlikely this is relevant
								continue
							}
							if _, ok := tags[tag]; !ok {
								tags[tag] = struct{}{}
							}
							// matcher names are also relevant in tech detection templates (ex: tech-detect)
							for k := range event.OperatorsResult.Matches {
								if _, ok := tags[k]; !ok {
									tags[k] = struct{}{}
								}
							}
						}
					}
					m.Unlock()
					_ = counter.Add(1)

					// TBD: should we show or hide tech detection results? what about matcher-status flag?
					_ = writer.WriteResult(event, s.opts.Output, s.opts.Progress, s.opts.IssuesClient)
				}
			}

			_, err := template.Executer.ExecuteWithResults(ctx)
			if err != nil {
				gologger.Verbose().Msgf("[%s] error executing template: %s\n", aurora.BrightYellow(template.ID), err)
				return
			}
		}(t)
	}
	sg.Wait()
	return mapsutil.GetKeys(tags), int(counter.Load())
}

func isHTTPFingerprintTemplate(template *templates.Template) bool {
	if template == nil {
		return false
	}
	templateType := template.Type()
	return templateType == templateTypes.HTTPProtocol ||
		templateType == templateTypes.HeadlessProtocol ||
		template.HasHTTPRequest() ||
		template.HasHeadlessRequest()
}

// normalizeAppName normalizes app name
func normalizeAppName(appName string) string {
	if strings.Contains(appName, ":") {
		if parts := strings.Split(appName, ":"); len(parts) == 2 {
			appName = parts[0]
		}
	}
	return strings.ToLower(appName)
}
