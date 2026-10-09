package offlinehttp

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"ManScan/internal/tests/testutils"
	"ManScan/pkg/input/types"
	"ManScan/pkg/model"
	"ManScan/pkg/model/types/severity"
	"ManScan/pkg/operators"
	"ManScan/pkg/operators/matchers"
	"ManScan/pkg/output"
	"ManScan/pkg/progress"
	"ManScan/pkg/protocols/common/contextargs"
	urlutil "github.com/projectdiscovery/utils/url"
)

func TestExecuteWithResultsUsesReqRespResponse(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &Request{}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "offline-export",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
	})
	counter := &countingProgress{Progress: executerOpts.Progress}
	executerOpts.Progress = counter
	ops := &operators.Operators{
		Matchers: []*matchers.Matcher{{
			Part:  "body",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{`"id":"1"`},
		}},
	}
	require.NoError(t, ops.Compile())
	executerOpts.Operators = []*operators.Operators{ops}
	require.NoError(t, request.Compile(executerOpts))

	parsedURL, err := urlutil.ParseAbsoluteURL("http://localhost:8087/scans", false)
	require.NoError(t, err)

	rawResponse := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"id\":\"1\"}\n"
	input := contextargs.New(t.Context())
	input.MetaInput.Input = parsedURL.String()
	input.MetaInput.ReqResp = &types.RequestResponse{
		URL: *parsedURL,
		Response: &types.HttpResponse{
			Raw: rawResponse,
		},
	}

	var gotEvent *output.InternalWrappedEvent
	err = request.ExecuteWithResults(input, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event
	})
	require.NoError(t, err)
	require.NotNil(t, gotEvent)
	require.True(t, gotEvent.HasOperatorResult())
	require.True(t, gotEvent.OperatorsResult.Matched)
	require.Equal(t, int64(1), counter.requests.Load())
}

type countingProgress struct {
	progress.Progress
	requests       atomic.Int64
	actualRequests atomic.Int64
	failedRequests atomic.Int64
	addedTotal     atomic.Int64
}

func (c *countingProgress) IncrementRequests() {
	c.requests.Add(1)
	if c.Progress != nil {
		c.Progress.IncrementRequests()
	}
}

func (c *countingProgress) IncrementActualRequests() {
	c.actualRequests.Add(1)
	if c.Progress != nil {
		c.Progress.IncrementActualRequests()
	}
}

func (c *countingProgress) IncrementFailedRequestsBy(count int64) {
	c.failedRequests.Add(count)
	if c.Progress != nil {
		c.Progress.IncrementFailedRequestsBy(count)
	}
}

func (c *countingProgress) AddToTotal(delta int64) {
	c.addedTotal.Add(delta)
	if c.Progress != nil {
		c.Progress.AddToTotal(delta)
	}
}

func TestExecuteWithResultsCountsEachOfflineFile(t *testing.T) {
	options := testutils.DefaultOptions
	options.BulkSize = 2
	testutils.Init(options)

	request := &Request{}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "offline-directory",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
	})
	counter := &countingProgress{Progress: executerOpts.Progress}
	executerOpts.Progress = counter
	executerOpts.Operators = []*operators.Operators{{}}
	require.NoError(t, request.Compile(executerOpts))

	tempDir := t.TempDir()
	rawResponse := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
	for _, name := range []string{"one.txt", "two.txt", "three.txt"} {
		require.NoError(t, os.WriteFile(filepath.Join(tempDir, name), []byte(rawResponse), 0o600))
	}

	var events atomic.Int64
	err := request.ExecuteWithResults(contextargs.NewWithInput(t.Context(), tempDir), nil, nil, func(*output.InternalWrappedEvent) {
		events.Add(1)
	})
	require.NoError(t, err)
	require.Equal(t, int64(3), events.Load())
	require.Equal(t, int64(3), counter.actualRequests.Load())
	require.Equal(t, int64(3), counter.requests.Load())
	require.Zero(t, counter.failedRequests.Load())
	require.Equal(t, int64(2), counter.addedTotal.Load())
}

func TestExecuteWithResultsSkipsWhenNoResponseOnReqResp(t *testing.T) {
	options := testutils.DefaultOptions
	options.BulkSize = 1
	testutils.Init(options)

	request := &Request{}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "offline-export-empty",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
	})
	executerOpts.Operators = []*operators.Operators{{}}
	require.NoError(t, request.Compile(executerOpts))

	parsedURL, err := urlutil.ParseAbsoluteURL("http://example.com/", false)
	require.NoError(t, err)

	input := contextargs.New(t.Context())
	// URL-shaped input would fail filepath walk; without Response we fall through.
	input.MetaInput.Input = parsedURL.String()
	input.MetaInput.ReqResp = &types.RequestResponse{URL: *parsedURL}

	err = request.ExecuteWithResults(input, nil, nil, func(event *output.InternalWrappedEvent) {
		t.Fatalf("unexpected event: %#v", event)
	})
	// getInputPaths on a URL yields no files; should not panic and should return nil.
	require.NoError(t, err)
}
