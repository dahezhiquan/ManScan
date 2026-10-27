package flow

import (
	"testing"

	"ManScan/pkg/protocols"
	templateTypes "ManScan/pkg/templates/types"
	"github.com/stretchr/testify/require"
)

type estimateRequest struct {
	protocols.Request
	id       string
	requests int
}

func (r *estimateRequest) GetID() string                    { return r.id }
func (r *estimateRequest) Requests() int                    { return r.requests }
func (r *estimateRequest) Type() templateTypes.ProtocolType { return templateTypes.HTTPProtocol }

func TestEstimateRequestsIncludesStaticFlowIterations(t *testing.T) {
	requests := []protocols.Request{
		&estimateRequest{id: "get", requests: 1},
		&estimateRequest{id: "posts", requests: 2},
	}

	got := EstimateRequests(requests, `for (let endpoint of ["/", "/index.php"]) { http("get"); http("posts"); }`)
	require.Equal(t, 6, got)
}

func TestEstimateRequestsUsesLargestConditionalBranch(t *testing.T) {
	requests := []protocols.Request{
		&estimateRequest{id: "first", requests: 1},
		&estimateRequest{id: "second", requests: 2},
	}

	got := EstimateRequests(requests, `if (condition) { http("first"); } else { http("second"); http("first"); }`)
	require.Equal(t, 3, got)
}

func TestEstimateRequestsFallsBackForDynamicLoopSource(t *testing.T) {
	requests := []protocols.Request{
		&estimateRequest{id: "first", requests: 1},
	}

	got := EstimateRequests(requests, `for (let endpoint of endpoints) { http("first"); }`)
	require.Equal(t, 1, got)
}

type estimateProgress struct {
	added int64
}

func (p *estimateProgress) Stop()                           {}
func (p *estimateProgress) Init(int64, int, int64)          {}
func (p *estimateProgress) AddToTotal(delta int64)          { p.added += delta }
func (p *estimateProgress) IncrementRequests()              {}
func (p *estimateProgress) IncrementActualRequests()        {}
func (p *estimateProgress) SetRequests(uint64)              {}
func (p *estimateProgress) IncrementMatched()               {}
func (p *estimateProgress) IncrementErrorsBy(int64)         {}
func (p *estimateProgress) IncrementFailedRequestsBy(int64) {}

func TestFlowRuntimeEstimateGrowsForDynamicLoop(t *testing.T) {
	progress := &estimateProgress{}
	executor := &FlowExecutor{
		estimatedRequests: 1,
		options:           &protocols.ExecutorOptions{Progress: progress},
	}
	request := &estimateRequest{requests: 1}

	executor.recordScheduledRequest(request)
	executor.recordScheduledRequest(request)
	executor.recordScheduledRequest(request)

	require.Equal(t, int64(2), progress.added)
}
