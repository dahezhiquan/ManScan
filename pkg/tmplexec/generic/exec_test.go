package generic

import (
	"context"
	"sync/atomic"
	"testing"

	"ManScan/pkg/model"
	"ManScan/pkg/operators"
	"ManScan/pkg/operators/extractors"
	"ManScan/pkg/operators/matchers"
	"ManScan/pkg/output"
	"ManScan/pkg/protocols"
	"ManScan/pkg/protocols/common/contextargs"
	"ManScan/pkg/scan"
	templateTypes "ManScan/pkg/templates/types"
	"ManScan/pkg/types"
	"github.com/stretchr/testify/require"
)

type progressCounter struct {
	skipped int64
}

func (p *progressCounter) Stop()                                {}
func (p *progressCounter) Init(int64, int, int64)               {}
func (p *progressCounter) AddToTotal(int64)                     {}
func (p *progressCounter) IncrementRequests()                   {}
func (p *progressCounter) IncrementActualRequests()             {}
func (p *progressCounter) SetRequests(uint64)                   {}
func (p *progressCounter) IncrementMatched()                    {}
func (p *progressCounter) IncrementErrorsBy(int64)              {}
func (p *progressCounter) IncrementFailedRequestsBy(int64)      {}
func (p *progressCounter) IncrementSkippedRequests(count int64) { p.skipped += count }

type fakeRequest struct {
	id       string
	requests int
	match    bool
}

func (r *fakeRequest) Compile(*protocols.ExecutorOptions) error { return nil }
func (r *fakeRequest) Requests() int                            { return r.requests }
func (r *fakeRequest) GetID() string                            { return r.id }
func (r *fakeRequest) Match(map[string]interface{}, *matchers.Matcher) (bool, []string) {
	return false, nil
}
func (r *fakeRequest) Extract(map[string]interface{}, *extractors.Extractor) map[string]struct{} {
	return nil
}
func (r *fakeRequest) ExecuteWithResults(_ *contextargs.Context, _, _ output.InternalEvent, callback protocols.OutputEventCallback) error {
	if r.match {
		callback(&output.InternalWrappedEvent{OperatorsResult: &operators.Result{Matched: true}})
	}
	return nil
}
func (r *fakeRequest) MakeResultEventItem(*output.InternalWrappedEvent) *output.ResultEvent {
	return nil
}
func (r *fakeRequest) MakeResultEvent(*output.InternalWrappedEvent) []*output.ResultEvent {
	return nil
}
func (r *fakeRequest) GetCompiledOperators() []*operators.Operators { return nil }
func (r *fakeRequest) Type() templateTypes.ProtocolType             { return templateTypes.HTTPProtocol }

func TestGenericStopAtFirstMatchCompletesRemainingRequests(t *testing.T) {
	progress := &progressCounter{}
	options := &protocols.ExecutorOptions{
		Options:          types.DefaultOptions(),
		Progress:         progress,
		StopAtFirstMatch: true,
		TemplateInfo:     model.Info{Name: "test"},
	}
	requests := []protocols.Request{
		&fakeRequest{id: "first", requests: 1, match: true},
		&fakeRequest{id: "second", requests: 2},
		&fakeRequest{id: "third", requests: 3},
	}

	engine := NewGenericEngine(requests, options, &atomic.Bool{})
	err := engine.ExecuteWithResults(scan.NewScanContext(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com")))
	require.NoError(t, err)
	require.Equal(t, int64(5), progress.skipped)
}
