package core

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"ManScan/pkg/input/provider"
	"ManScan/pkg/output"
	"ManScan/pkg/protocols/common/contextargs"
	"ManScan/pkg/templates"
	"ManScan/pkg/templates/types"
	"ManScan/pkg/types/scanstrategy"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
)

// Execute takes a list of templates/workflows that have been compiled
// and executes them based on provided concurrency options.
//
// All the execution logic for the templates/workflows happens in this part
// of the engine.
func (e *Engine) Execute(ctx context.Context, templates []*templates.Template, target provider.InputProvider) *atomic.Bool {
	return e.ExecuteScanWithOpts(ctx, templates, target, false)
}

// ExecuteWithResults a list of templates with results
func (e *Engine) ExecuteWithResults(ctx context.Context, templatesList []*templates.Template, target provider.InputProvider, callback func(*output.ResultEvent)) *atomic.Bool {
	e.Callback = callback
	return e.ExecuteScanWithOpts(ctx, templatesList, target, false)
}

// ExecuteScanWithOpts executes scan with given scanStrategy
func (e *Engine) ExecuteScanWithOpts(ctx context.Context, templatesList []*templates.Template, target provider.InputProvider, noCluster bool) *atomic.Bool {
	results := &atomic.Bool{}
	selfcontainedWg := &sync.WaitGroup{}
	targetStats := e.targetExecutionStats(target, hasTargetAwareNetworkRequests(templatesList))

	totalReqBeforeCluster := getRequestCountForTargets(templatesList, targetStats)

	// attempt to cluster templates if noCluster is false
	var finalTemplates []*templates.Template
	clusterCount := 0
	if !noCluster {
		var clusterMappings map[string][]string
		finalTemplates, clusterCount, clusterMappings = templates.ClusterTemplates(templatesList, e.executerOpts)
		// Store cluster mappings in executerOpts for SDK access (thread-safe)
		if clusterMappings != nil {
			e.executerOpts.ClusterMappings = types.NewClusterMappingsMap(clusterMappings)
		}
	} else {
		finalTemplates = templatesList
	}

	totalReqAfterClustering := getRequestCountForTargets(finalTemplates, targetStats)

	if !noCluster && totalReqAfterClustering < totalReqBeforeCluster {
		e.Logger.Info().Msgf("Templates clustered: %d (Reduced %d Requests)", clusterCount, totalReqBeforeCluster-totalReqAfterClustering)
	}

	// 0 matches means no templates were found in the directory
	if len(finalTemplates) == 0 {
		if os.Getenv("MANSCAN_ASSET_DOMAIN_FINGERPRINT_TARGET_EVENTS") == "preflight" {
			target.Iterate(func(value *contextargs.MetaInput) bool {
				e.emitFingerprintTargetCompleted(value.Input)
				return true
			})
		}
		return &atomic.Bool{}
	}

	if e.executerOpts.Progress != nil {
		// Notes:
		// workflow requests are not counted as they can be conditional
		// templateList count is the unique set of templates executable for at
		// least one target (before clustering).
		// totalReqAfterClustering is total requests count after clustering
		e.executerOpts.Progress.Init(
			targetStats.totalTargets,
			countExecutableTemplates(templatesList, targetStats),
			totalReqAfterClustering,
		)
		if setter, ok := e.executerOpts.Progress.(interface{ SetPreClusterTotal(int64) }); ok {
			setter.SetPreClusterTotal(totalReqBeforeCluster)
		}
	}

	if stringsutil.EqualFoldAny(e.options.ScanStrategy, scanstrategy.Auto.String(), "") {
		// TODO: this is only a placeholder, auto scan strategy should choose scan strategy
		// based on no of hosts , templates , stream and other optimization parameters
		e.options.ScanStrategy = scanstrategy.TemplateSpray.String()
	}

	filtered := []*templates.Template{}
	selfContained := []*templates.Template{}
	// Filter Self Contained templates since they are not bound to target
	for _, v := range finalTemplates {
		if v.SelfContained {
			selfContained = append(selfContained, v)
		} else {
			filtered = append(filtered, v)
		}
	}

	// Execute All SelfContained in parallel
	e.executeAllSelfContained(ctx, selfContained, results, selfcontainedWg)

	strategyResult := &atomic.Bool{}
	switch e.options.ScanStrategy {
	case scanstrategy.TemplateSpray.String():
		strategyResult = e.executeTemplateSpray(ctx, filtered, target)
	case scanstrategy.HostSpray.String():
		strategyResult = e.executeHostSpray(ctx, filtered, target)
	}

	results.CompareAndSwap(false, strategyResult.Load())

	selfcontainedWg.Wait()
	return results
}

// executeTemplateSpray executes scan using template spray strategy where targets are iterated over each template
func (e *Engine) executeTemplateSpray(ctx context.Context, templatesList []*templates.Template, target provider.InputProvider) *atomic.Bool {
	results := &atomic.Bool{}

	// wp is workpool that contains different waitgroups for
	// headless and non-headless templates
	wp := e.GetWorkPool()
	defer wp.Wait()

	for _, template := range templatesList {

		select {
		case <-ctx.Done():
			return results
		default:
		}

		// resize check point - nop if there are no changes
		wp.RefreshWithConfig(e.GetWorkPoolConfig())

		templateType := template.Type()
		var wg *syncutil.AdaptiveWaitGroup
		if templateType == types.HeadlessProtocol {
			wg = wp.Headless
		} else {
			wg = wp.Default
		}

		if err := wg.AddWithContext(ctx); err != nil {
			return results
		}
		usesSharedTemplateBudget := templateType != types.HeadlessProtocol
		if usesSharedTemplateBudget {
			if err := e.options.AcquireTemplateThread(ctx); err != nil {
				wg.Done()
				return results
			}
		}
		go func(tpl *templates.Template, sharedBudget bool) {
			defer wg.Done()
			if sharedBudget {
				defer e.options.ReleaseTemplateThread()
			}
			// All other request types are executed here
			// Note: executeTemplateWithTargets creates goroutines and blocks
			// given template is executed on all targets
			e.executeTemplateWithTargets(ctx, tpl, target, results)
		}(template, usesSharedTemplateBudget)
	}
	return results
}

// executeHostSpray executes scan using host spray strategy where templates are iterated over each target
func (e *Engine) executeHostSpray(ctx context.Context, templatesList []*templates.Template, target provider.InputProvider) *atomic.Bool {
	results := &atomic.Bool{}
	wp, _ := syncutil.New(syncutil.WithSize(e.options.BulkSize + e.options.HeadlessBulkSize))
	defer wp.Wait()

	target.Iterate(func(value *contextargs.MetaInput) bool {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		wp.Add()
		go func(targetval *contextargs.MetaInput) {
			defer wp.Done()
			e.executeTemplatesOnTarget(ctx, templatesList, targetval, results)
			if ctx.Err() == nil && os.Getenv("MANSCAN_ASSET_DOMAIN_FINGERPRINT_TARGET_EVENTS") == "preflight" {
				e.emitFingerprintTargetCompleted(targetval.Input)
			}
		}(value)
		return true
	})
	return results
}

func (e *Engine) emitFingerprintTargetCompleted(target string) {
	if e.executerOpts == nil || e.executerOpts.Output == nil {
		return
	}
	if emitter, ok := e.executerOpts.Output.(interface{ WriteFingerprintTargetCompleted(string) error }); ok {
		if err := emitter.WriteFingerprintTargetCompleted(target); err != nil && e.Logger != nil {
			e.Logger.Warning().Msgf("Could not emit fingerprint completion for %s: %s", target, err)
		}
	}
}

type targetExecutionStats struct {
	totalTargets       int64
	httpCapableTargets int64
	inputs             []targetCountInput
}

type targetCountInput struct {
	input       string
	httpCapable bool
}

func hasTargetAwareNetworkRequests(templateList []*templates.Template) bool {
	for _, template := range templateList {
		if template != nil && !template.SelfContained && template.Flow == "" && len(template.RequestsNetwork) > 0 {
			return true
		}
	}
	return false
}

func (e *Engine) targetExecutionStats(target provider.InputProvider, trackNetworkTargets bool) targetExecutionStats {
	if target == nil {
		return targetExecutionStats{}
	}

	totalTargets := target.Count()
	if totalTargets <= 0 {
		return targetExecutionStats{}
	}

	stats := targetExecutionStats{
		totalTargets:       totalTargets,
		httpCapableTargets: totalTargets,
	}
	hasFingerprintCache := e != nil && e.executerOpts != nil && e.executerOpts.AssetDomainFingerprintCache != nil
	if !hasFingerprintCache && !trackNetworkTargets {
		return stats
	}
	stats.httpCapableTargets = 0
	iteratedTargets := int64(0)
	target.Iterate(func(value *contextargs.MetaInput) bool {
		iteratedTargets++
		httpCapable := value == nil || !hasFingerprintCache || !e.executerOpts.AssetDomainFingerprintCache.HTTPProbeFailed(value.Input)
		if httpCapable {
			stats.httpCapableTargets++
		}
		if trackNetworkTargets && value != nil && value.Port() != "" {
			stats.inputs = append(stats.inputs, targetCountInput{input: value.Input, httpCapable: httpCapable})
		}
		return true
	})
	// A provider may report more targets than it exposes through Iterate while
	// loading a stream. Unknown targets must remain eligible for HTTP templates.
	if iteratedTargets < totalTargets {
		stats.httpCapableTargets += totalTargets - iteratedTargets
	}
	if stats.httpCapableTargets > totalTargets {
		stats.httpCapableTargets = totalTargets
	}
	return stats
}

func countExecutableTemplates(templateList []*templates.Template, targetStats targetExecutionStats) int {
	if targetStats.totalTargets <= 0 {
		return 0
	}

	seenIDs := make(map[string]struct{}, len(templateList))
	seenPointers := make(map[*templates.Template]struct{})
	count := 0
	for _, template := range templateList {
		if template == nil {
			continue
		}
		if !templateCanExecuteForTargets(template, targetStats) {
			continue
		}

		templateID := strings.TrimSpace(template.ID)
		if templateID == "" {
			templateID = strings.TrimSpace(template.Path)
		}
		if templateID != "" {
			if _, ok := seenIDs[templateID]; ok {
				continue
			}
			seenIDs[templateID] = struct{}{}
		} else {
			if _, ok := seenPointers[template]; ok {
				continue
			}
			seenPointers[template] = struct{}{}
		}
		count++
	}
	return count
}

func getRequestCountForTargets(templateList []*templates.Template, targetStats targetExecutionStats) int64 {
	if targetStats.totalTargets <= 0 {
		return 0
	}

	var count int64
	for _, template := range templateList {
		if template == nil {
			continue
		}
		// Workflow requests are conditional and cannot be estimated here.
		if len(template.Workflows) > 0 {
			continue
		}
		targetCount := targetStats.totalTargets
		httpBased := !template.SelfContained && isHTTPBasedTemplate(template)
		if httpBased {
			targetCount = targetStats.httpCapableTargets
		}
		count += int64(template.TotalRequests) * targetCount
		if !template.SelfContained && len(template.RequestsNetwork) > 0 {
			for _, input := range targetStats.inputs {
				if httpBased && !input.httpCapable {
					continue
				}
				count += int64(template.EstimatedRequestsForTarget(input.input) - template.TotalRequests)
			}
		}
	}
	return count
}

func templateCanExecuteForTargets(template *templates.Template, targetStats targetExecutionStats) bool {
	if template == nil || targetStats.totalTargets <= 0 {
		return false
	}
	if template.SelfContained || !isHTTPBasedTemplate(template) {
		return true
	}
	return targetStats.httpCapableTargets > 0
}
