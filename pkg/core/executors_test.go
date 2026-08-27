package core

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	inputtypes "ManScan/pkg/input/types"
	"ManScan/pkg/output"
	"ManScan/pkg/protocols"
	"ManScan/pkg/protocols/common/contextargs"
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
