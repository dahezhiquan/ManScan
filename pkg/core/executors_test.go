package core

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	inputtypes "ManScan/pkg/input/types"
	"ManScan/pkg/output"
	"ManScan/pkg/protocols"
	"ManScan/pkg/protocols/common/assetdomainfingerprint"
	"ManScan/pkg/protocols/common/contextargs"
	httpprotocol "ManScan/pkg/protocols/http"
	"ManScan/pkg/protocols/network"
	"ManScan/pkg/scan"
	"ManScan/pkg/templates"
	tmpltypes "ManScan/pkg/templates/types"
	"ManScan/pkg/types"
)

// fakeExecuter is a simple stub for protocols.Executer used to test executeTemplateOnInput
type fakeExecuter struct {
	withResults bool
}

func (f *fakeExecuter) Compile() error                              { return nil }
func (f *fakeExecuter) Requests() int                               { return 1 }
func (f *fakeExecuter) Execute(ctx *scan.ScanContext) (bool, error) { return !f.withResults, nil }
func (f *fakeExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	if !f.withResults {
		return nil, nil
	}
	return []*output.ResultEvent{{Host: "h"}}, nil
}

type countingExecuter struct {
	count atomic.Int32
}

func (c *countingExecuter) Compile() error { return nil }
func (c *countingExecuter) Requests() int  { return 1 }
func (c *countingExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	c.count.Add(1)
	return true, nil
}
func (c *countingExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	c.count.Add(1)
	return []*output.ResultEvent{{Host: ctx.Input.MetaInput.Input}}, nil
}

// newTestEngine creates a minimal Engine for tests
func newTestEngine() *Engine {
	return New(&types.Options{})
}

func Test_executeTemplateOnInput_CallbackPath(t *testing.T) {
	e := newTestEngine()
	called := 0
	e.Callback = func(*output.ResultEvent) { called++ }

	tpl := &templates.Template{}
	tpl.Executer = &fakeExecuter{withResults: true}

	ok, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected match true")
	}
	if called == 0 {
		t.Fatalf("expected callback to be called")
	}
}

func Test_executeTemplateOnInput_ExecutePath(t *testing.T) {
	e := newTestEngine()
	tpl := &templates.Template{}
	tpl.Executer = &fakeExecuter{withResults: false}

	ok, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected match true from Execute path")
	}
}

type fakeExecuterErr struct{}

func (f *fakeExecuterErr) Compile() error                              { return nil }
func (f *fakeExecuterErr) Requests() int                               { return 1 }
func (f *fakeExecuterErr) Execute(ctx *scan.ScanContext) (bool, error) { return false, nil }
func (f *fakeExecuterErr) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, fmt.Errorf("boom")
}

func Test_executeTemplateOnInput_CallbackErrorPropagates(t *testing.T) {
	e := newTestEngine()
	e.Callback = func(*output.ResultEvent) {}
	tpl := &templates.Template{}
	tpl.Executer = &fakeExecuterErr{}

	ok, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "x"})
	if err == nil {
		t.Fatalf("expected error to propagate")
	}
	if ok {
		t.Fatalf("expected match to be false on error")
	}
}

func TestExecuteTemplateOnInputReportsLifecycle(t *testing.T) {
	e := newTestEngine()
	var events []TemplateExecutionEvent
	e.SetTemplateExecutionCallback(func(event TemplateExecutionEvent) {
		events = append(events, event)
	})

	tpl := &templates.Template{ID: "template-id", Path: "http/example.yaml"}
	tpl.Executer = &fakeExecuter{withResults: false}

	_, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []TemplateExecutionEvent{
		{TemplateID: "template-id", TemplatePath: "http/example.yaml", Target: "https://example.com", State: TemplateExecutionStarted},
		{TemplateID: "template-id", TemplatePath: "http/example.yaml", Target: "https://example.com", State: TemplateExecutionFinished},
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("unexpected lifecycle events: got %#v want %#v", events, want)
	}
}

func TestExecuteTemplateOnInputReportsCancellationOnFinish(t *testing.T) {
	e := newTestEngine()
	var finished TemplateExecutionEvent
	e.SetTemplateExecutionCallback(func(event TemplateExecutionEvent) {
		if event.State == TemplateExecutionFinished {
			finished = event
		}
	})
	tpl := &templates.Template{ID: "interrupted"}
	tpl.Executer = &fakeExecuter{withResults: false}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = e.executeTemplateOnInput(ctx, tpl, &contextargs.MetaInput{Input: "target"})
	if finished.ContextErr != context.Canceled {
		t.Fatalf("got finish context error %v, want context canceled", finished.ContextErr)
	}
}

type fakeTargetProvider struct {
	values []*contextargs.MetaInput
}

func (f *fakeTargetProvider) Count() int64 { return int64(len(f.values)) }
func (f *fakeTargetProvider) Iterate(cb func(value *contextargs.MetaInput) bool) {
	for _, v := range f.values {
		if !cb(v) {
			return
		}
	}
}
func (f *fakeTargetProvider) Set(string, string) {}
func (f *fakeTargetProvider) SetWithProbe(string, string, inputtypes.InputLivenessProbe) error {
	return nil
}
func (f *fakeTargetProvider) SetWithExclusions(string, string) error { return nil }
func (f *fakeTargetProvider) InputType() string                      { return "test" }
func (f *fakeTargetProvider) Close()                                 {}

type recordingProgress struct {
	hostCount              int64
	templateCount          int
	requestCount           int64
	preClusterRequestCount int64
	skippedRequestCount    int64
}

func (p *recordingProgress) Stop() {}

func (p *recordingProgress) Init(hostCount int64, rulesCount int, requestCount int64) {
	p.hostCount = hostCount
	p.templateCount = rulesCount
	p.requestCount = requestCount
}

func (p *recordingProgress) SetPreClusterTotal(requestCount int64) {
	p.preClusterRequestCount = requestCount
}

func (p *recordingProgress) AddToTotal(int64)         {}
func (p *recordingProgress) IncrementRequests()       {}
func (p *recordingProgress) IncrementActualRequests() {}
func (p *recordingProgress) SetRequests(uint64)       {}
func (p *recordingProgress) IncrementSkippedRequests(count int64) {
	p.skippedRequestCount += count
}
func (p *recordingProgress) IncrementMatched()               {}
func (p *recordingProgress) IncrementErrorsBy(int64)         {}
func (p *recordingProgress) IncrementFailedRequestsBy(int64) {}

type alwaysSkipHostErrorsCache struct{}

func (c *alwaysSkipHostErrorsCache) SetVerbose(bool) {}
func (c *alwaysSkipHostErrorsCache) Close()          {}
func (c *alwaysSkipHostErrorsCache) Check(string, *contextargs.Context) bool {
	return true
}
func (c *alwaysSkipHostErrorsCache) Remove(*contextargs.Context)                    {}
func (c *alwaysSkipHostErrorsCache) MarkFailed(string, *contextargs.Context, error) {}
func (c *alwaysSkipHostErrorsCache) MarkFailedOrRemove(string, *contextargs.Context, error) {
}
func (c *alwaysSkipHostErrorsCache) IsPermanentErr(*contextargs.Context, error) bool {
	return false
}

type slowExecuter struct{}

func (s *slowExecuter) Compile() error { return nil }
func (s *slowExecuter) Requests() int  { return 1 }
func (s *slowExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	select {
	case <-ctx.Context().Done():
		return false, ctx.Context().Err()
	case <-time.After(200 * time.Millisecond):
		return true, nil
	}
}

type adaptiveConcurrencyExecuter struct {
	delay       time.Duration
	started     atomic.Int32
	completed   atomic.Int32
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	onStart     func(int32)
}

func (s *adaptiveConcurrencyExecuter) Compile() error { return nil }
func (s *adaptiveConcurrencyExecuter) Requests() int  { return 1 }
func (s *adaptiveConcurrencyExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	started := s.started.Add(1)
	if s.onStart != nil {
		s.onStart(started)
	}
	inFlight := s.inFlight.Add(1)
	for {
		maximum := s.maxInFlight.Load()
		if inFlight <= maximum || s.maxInFlight.CompareAndSwap(maximum, inFlight) {
			break
		}
	}
	defer s.inFlight.Add(-1)

	select {
	case <-ctx.Context().Done():
		return false, ctx.Context().Err()
	case <-time.After(s.delay):
		s.completed.Add(1)
		return true, nil
	}
}
func (s *adaptiveConcurrencyExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func TestExecuteTemplateSprayRefreshesDynamicTemplateConcurrency(t *testing.T) {
	const (
		templateCount      = 8
		initialConcurrency = 2
		finalConcurrency   = 8
	)

	var currentConcurrency atomic.Int32
	currentConcurrency.Store(initialConcurrency)
	var expandOnce sync.Once
	executer := &adaptiveConcurrencyExecuter{
		delay: 100 * time.Millisecond,
		onStart: func(started int32) {
			if started == initialConcurrency {
				expandOnce.Do(func() { currentConcurrency.Store(finalConcurrency) })
			}
		},
	}
	options := &types.Options{
		BulkSize:                1,
		TemplateThreads:         initialConcurrency,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
	}
	options.SetTemplateThreadsProvider(func() int { return int(currentConcurrency.Load()) })
	if got := options.Copy().CurrentTemplateThreads(); got != initialConcurrency {
		t.Fatalf("copied options returned concurrency %d, expected %d", got, initialConcurrency)
	}
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.NetworkProtocol,
	})
	templatesList := make([]*templates.Template, 0, templateCount)
	for index := range templateCount {
		templatesList = append(templatesList, &templates.Template{ID: fmt.Sprintf("adaptive-%d", index), Executer: executer})
	}
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "slow-target"}}}

	started := time.Now()
	engine.ExecuteScanWithOpts(context.Background(), templatesList, targets, true)
	elapsed := time.Since(started)

	if got := executer.completed.Load(); got != templateCount {
		t.Fatalf("completed %d templates, expected %d", got, templateCount)
	}
	if got := executer.maxInFlight.Load(); got <= initialConcurrency {
		t.Fatalf("maximum concurrency stayed at %d; expected it to expand beyond %d", got, initialConcurrency)
	}
	if elapsed >= 350*time.Millisecond {
		t.Fatalf("dynamic execution took %s; fixed concurrency would take about 400ms", elapsed)
	}
	t.Logf("dynamic execution completed all %d templates in %s with peak concurrency %d", templateCount, elapsed, executer.maxInFlight.Load())
}

func TestExecuteTemplateSprayHonorsSharedConcurrencyLimiter(t *testing.T) {
	const (
		templateCount = 8
		sharedBudget  = 2
	)

	tokens := make(chan struct{}, sharedBudget)
	executer := &adaptiveConcurrencyExecuter{delay: 50 * time.Millisecond}
	options := &types.Options{
		BulkSize:                1,
		TemplateThreads:         templateCount,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
	}
	options.SetTemplateThreadsLimiter(func(ctx context.Context) error {
		select {
		case tokens <- struct{}{}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func() {
		<-tokens
	})
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.NetworkProtocol,
	})
	templatesList := make([]*templates.Template, 0, templateCount)
	for index := range templateCount {
		templatesList = append(templatesList, &templates.Template{ID: fmt.Sprintf("shared-limit-%d", index), Executer: executer})
	}

	engine.ExecuteScanWithOpts(context.Background(), templatesList,
		&fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "slow-target"}}}, true)

	if got := executer.completed.Load(); got != templateCount {
		t.Fatalf("completed %d templates, expected %d", got, templateCount)
	}
	if got := executer.maxInFlight.Load(); got > sharedBudget {
		t.Fatalf("maximum concurrency was %d, shared budget is %d", got, sharedBudget)
	}
}

func TestExecuteSkipsHTTPTemplatesForHTTPInactiveTargets(t *testing.T) {
	httpAlive := false
	httpExecuter := &countingExecuter{}
	networkExecuter := &countingExecuter{}
	options := &types.Options{
		BulkSize:                1,
		TemplateThreads:         2,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
	}
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:    engine.Logger,
		Options:   options,
		ResumeCfg: types.NewResumeCfg(),
		AssetDomainFingerprintCache: assetdomainfingerprint.FromEntries([]assetdomainfingerprint.Entry{
			{Target: "mysql.example.com:3306", HTTPAlive: &httpAlive},
		}),
	})

	templatesList := []*templates.Template{
		{ID: "http-template", RequestsHTTP: []*httpprotocol.Request{{}}, Executer: httpExecuter},
		{ID: "network-template", RequestsNetwork: []*network.Request{{}}, Executer: networkExecuter},
	}
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "mysql.example.com:3306"}}}

	engine.ExecuteScanWithOpts(context.Background(), templatesList, targets, true)

	if got := httpExecuter.count.Load(); got != 0 {
		t.Fatalf("http template executed %d times, want 0", got)
	}
	if got := networkExecuter.count.Load(); got != 1 {
		t.Fatalf("network template executed %d times, want 1", got)
	}
}

func TestExecuteProgressCountsOnlyExecutableTemplates(t *testing.T) {
	httpAlive := false
	engine := New(&types.Options{})
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		AssetDomainFingerprintCache: assetdomainfingerprint.FromEntries([]assetdomainfingerprint.Entry{
			{Target: "mysql.example.com:3306", HTTPAlive: &httpAlive},
		}),
	})

	templatesList := []*templates.Template{
		{ID: "http-template", TotalRequests: 3, RequestsHTTP: []*httpprotocol.Request{{}}},
		{ID: "network-template", TotalRequests: 2, RequestsNetwork: []*network.Request{{}}},
		{ID: "network-template", TotalRequests: 2, RequestsNetwork: []*network.Request{{}}},
	}
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "mysql.example.com:3306"}}}
	targetStats := engine.targetExecutionStats(targets)

	if got := countExecutableTemplates(templatesList, targetStats); got != 1 {
		t.Fatalf("countExecutableTemplates() = %d, want 1", got)
	}
	if got := getRequestCountForTargets(templatesList, targetStats); got != 4 {
		t.Fatalf("getRequestCountForTargets() = %d, want 4", got)
	}
}

func TestExecuteScanInitializesFilteredProgress(t *testing.T) {
	httpAlive := false
	options := &types.Options{
		BulkSize:                1,
		TemplateThreads:         2,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
	}
	engine := New(options)
	progressClient := &recordingProgress{}
	httpExecuter := &countingExecuter{}
	networkExecuter := &countingExecuter{}
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:    engine.Logger,
		Options:   options,
		Progress:  progressClient,
		ResumeCfg: types.NewResumeCfg(),
		AssetDomainFingerprintCache: assetdomainfingerprint.FromEntries([]assetdomainfingerprint.Entry{
			{Target: "mysql.example.com:3306", HTTPAlive: &httpAlive},
		}),
	})

	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "mysql.example.com:3306"}}}
	engine.ExecuteScanWithOpts(context.Background(), []*templates.Template{
		{
			ID:            "http-template",
			TotalRequests: 3,
			RequestsHTTP:  []*httpprotocol.Request{{}},
			Executer:      httpExecuter,
		},
		{
			ID:              "network-template",
			TotalRequests:   2,
			RequestsNetwork: []*network.Request{{}},
			Executer:        networkExecuter,
		},
	}, targets, true)

	if progressClient.hostCount != 1 {
		t.Fatalf("progress host count = %d, want 1", progressClient.hostCount)
	}
	if progressClient.templateCount != 1 {
		t.Fatalf("progress template count = %d, want 1", progressClient.templateCount)
	}
	if progressClient.requestCount != 2 {
		t.Fatalf("progress request count = %d, want 2", progressClient.requestCount)
	}
	if progressClient.preClusterRequestCount != 2 {
		t.Fatalf("progress pre-cluster request count = %d, want 2", progressClient.preClusterRequestCount)
	}
	if got := httpExecuter.count.Load(); got != 0 {
		t.Fatalf("http template executed %d times, want 0", got)
	}
	if got := networkExecuter.count.Load(); got != 1 {
		t.Fatalf("network template executed %d times, want 1", got)
	}
}

func TestExecuteProgressKeepsHTTPTemplatesForMixedTargets(t *testing.T) {
	httpAlive := false
	engine := New(&types.Options{})
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{
		{Input: "mysql.example.com:3306"},
		{Input: "https://example.com"},
	}}
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		AssetDomainFingerprintCache: assetdomainfingerprint.FromEntries([]assetdomainfingerprint.Entry{
			{Target: "mysql.example.com:3306", HTTPAlive: &httpAlive},
		}),
	})

	templatesList := []*templates.Template{
		{ID: "http-template", TotalRequests: 3, RequestsHTTP: []*httpprotocol.Request{{}}},
		{ID: "network-template", TotalRequests: 2, RequestsNetwork: []*network.Request{{}}},
	}
	targetStats := engine.targetExecutionStats(targets)

	if got := countExecutableTemplates(templatesList, targetStats); got != 2 {
		t.Fatalf("countExecutableTemplates() = %d, want 2", got)
	}
	if got := getRequestCountForTargets(templatesList, targetStats); got != 7 {
		t.Fatalf("getRequestCountForTargets() = %d, want 7", got)
	}
}

func TestExecuteAllSelfContainedHonorsSharedConcurrencyLimiter(t *testing.T) {
	const (
		templateCount = 8
		sharedBudget  = 2
	)

	tokens := make(chan struct{}, sharedBudget)
	executer := &adaptiveConcurrencyExecuter{delay: 20 * time.Millisecond}
	options := &types.Options{}
	options.SetTemplateThreadsLimiter(func(ctx context.Context) error {
		select {
		case tokens <- struct{}{}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func() {
		<-tokens
	})
	engine := New(options)
	templatesList := make([]*templates.Template, 0, templateCount)
	for index := range templateCount {
		templatesList = append(templatesList, &templates.Template{ID: fmt.Sprintf("self-contained-%d", index), Executer: executer})
	}

	var results atomic.Bool
	var waitGroup sync.WaitGroup
	engine.executeAllSelfContained(context.Background(), templatesList, &results, &waitGroup)
	waitGroup.Wait()

	if got := executer.completed.Load(); got != templateCount {
		t.Fatalf("completed %d templates, expected %d", got, templateCount)
	}
	if got := executer.maxInFlight.Load(); got > sharedBudget {
		t.Fatalf("maximum concurrency was %d, shared budget is %d", got, sharedBudget)
	}
}
func (s *slowExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

type cancelAwareExecuter struct {
	started chan struct{}
}

func (s *cancelAwareExecuter) Compile() error { return nil }
func (s *cancelAwareExecuter) Requests() int  { return 1 }
func (s *cancelAwareExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	close(s.started)
	<-ctx.Context().Done()
	return false, ctx.Context().Err()
}
func (s *cancelAwareExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func Test_executeTemplateWithTargets_RespectsCancellation(t *testing.T) {
	e := newTestEngine()
	e.SetExecuterOptions(&protocols.ExecutorOptions{Logger: e.Logger, ResumeCfg: types.NewResumeCfg(), ProtocolType: tmpltypes.HTTPProtocol})

	tpl := &templates.Template{}
	tpl.Executer = &slowExecuter{}

	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "a"}, {Input: "b"}, {Input: "c"}}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var matched atomic.Bool
	e.executeTemplateWithTargets(ctx, tpl, targets, &matched)
}

func TestExecuteTemplateWithTargetsCountsHostErrorSkips(t *testing.T) {
	e := newTestEngine()
	progress := &recordingProgress{}
	e.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:          e.Logger,
		ResumeCfg:       types.NewResumeCfg(),
		ProtocolType:    tmpltypes.HTTPProtocol,
		HostErrorsCache: &alwaysSkipHostErrorsCache{},
		Progress:        progress,
	})

	tpl := &templates.Template{ID: "skip-template", TotalRequests: 3}
	tpl.Executer = &countingExecuter{}
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "https://example.com"}}}

	var matched atomic.Bool
	e.executeTemplateWithTargets(context.Background(), tpl, targets, &matched)

	if got := progress.skippedRequestCount; got != 3 {
		t.Fatalf("skippedRequestCount = %d, want 3", got)
	}
}

func TestExecuteTemplatesOnTargetCountsRemainingHostErrorSkips(t *testing.T) {
	e := New(&types.Options{
		BulkSize:                1,
		TemplateThreads:         1,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
	})
	progress := &recordingProgress{}
	e.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:          e.Logger,
		ResumeCfg:       types.NewResumeCfg(),
		ProtocolType:    tmpltypes.HTTPProtocol,
		HostErrorsCache: &alwaysSkipHostErrorsCache{},
		Progress:        progress,
	})

	templatesList := []*templates.Template{
		{ID: "first", TotalRequests: 2, Executer: &countingExecuter{}},
		{ID: "second", TotalRequests: 4, Executer: &countingExecuter{}},
	}

	var matched atomic.Bool
	e.executeTemplatesOnTarget(context.Background(), templatesList, &contextargs.MetaInput{Input: "https://example.com"}, &matched)

	if got := progress.skippedRequestCount; got != 6 {
		t.Fatalf("skippedRequestCount = %d, want 6", got)
	}
}

func Test_executeTemplateWithTargets_KeepsInFlightOnCancellation(t *testing.T) {
	e := newTestEngine()
	resumeCfg := types.NewResumeCfg()
	e.SetExecuterOptions(&protocols.ExecutorOptions{Logger: e.Logger, ResumeCfg: resumeCfg, ProtocolType: tmpltypes.HTTPProtocol})

	executer := &cancelAwareExecuter{started: make(chan struct{})}
	tpl := &templates.Template{ID: "cancel-template"}
	tpl.Executer = executer

	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "a"}}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		var matched atomic.Bool
		e.executeTemplateWithTargets(ctx, tpl, targets, &matched)
		close(done)
	}()

	select {
	case <-executer.started:
	case <-time.After(time.Second):
		t.Fatalf("template execution did not start")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("template execution did not stop after cancellation")
	}

	currentInfo := resumeCfg.Current[tpl.ID]
	if currentInfo == nil {
		t.Fatalf("resume current info missing")
	}
	if currentInfo.Completed {
		t.Fatalf("currentInfo.Completed = true, want false")
	}
	if !currentInfo.IsInFlight(0) {
		t.Fatalf("target index 0 was removed from in-flight after cancellation")
	}
}
