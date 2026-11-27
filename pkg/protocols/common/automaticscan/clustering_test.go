package automaticscan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"ManScan/internal/tests/testutils"
	"ManScan/pkg/catalog/config"
	"ManScan/pkg/catalog/disk"
	"ManScan/pkg/catalog/loader"
	"ManScan/pkg/input/provider"
	"ManScan/pkg/output"
	"ManScan/pkg/protocols/common/assetdomainfingerprint"
	"ManScan/pkg/protocols/common/contextargs"
	"ManScan/pkg/templates"
	"ManScan/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/stretchr/testify/require"
)

func TestAutomaticScanClusteringPreservesMappingAndResults(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("disabled=%t", disabled), func(t *testing.T) {
			root := t.TempDir()
			oldRoot, oldConfig := config.DefaultConfig.TemplatesDirectory, config.DefaultConfig.GetConfigDir()
			config.DefaultConfig.SetTemplatesDir(root)
			config.DefaultConfig.SetConfigDir(t.TempDir())
			t.Cleanup(func() {
				config.DefaultConfig.SetTemplatesDir(oldRoot)
				config.DefaultConfig.SetConfigDir(oldConfig)
			})

			// One fingerprint tag comes from the original ID, the other from its name.
			fixtures := []struct{ id, name, tags, path string }{
				{"alpha-detect", "First fingerprint", "tech,alpha", "/fingerprint"},
				{"second-detect", "Bravo Service", "tech,bravo", "/fingerprint"},
				{"alpha-vuln", "Alpha vulnerability", "alpha", "/vulnerable"},
				{"bravo-vuln", "Bravo vulnerability", "bravo", "/vulnerable"},
			}
			for _, fixture := range fixtures {
				content := fmt.Sprintf(`id: %s
info:
  name: %s
  author: test
  severity: info
  tags: %s
http:
  - method: GET
    path:
      - "{{BaseURL}}%s"
    matchers:
      - type: word
        part: body
        words: ["clustering-fixture"]
`, fixture.id, fixture.name, fixture.tags, fixture.path)
				require.NoError(t, os.WriteFile(filepath.Join(root, fixture.id+".yaml"), []byte(content), 0o600))
			}

			var fingerprintRequests, vulnerabilityRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/fingerprint":
					fingerprintRequests.Add(1)
				case "/vulnerable":
					vulnerabilityRequests.Add(1)
				default:
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write([]byte("clustering-fixture"))
			}))
			t.Cleanup(server.Close)

			options := testutils.DefaultOptions.Copy()
			options.ExecutionId = t.Name()
			options.Templates = []string{root}
			options.DisableClustering = disabled
			options.TemplateLoadingConcurrency = 1
			options.HeadlessTemplateThreads = 1
			options.HeadlessBulkSize = 1
			options.Logger = &gologger.Logger{}
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })
			execOptions := testutils.NewMockExecuterOptions(options, nil)
			t.Cleanup(execOptions.RateLimiter.Stop)
			execOptions.Catalog = disk.NewCatalog(root)
			execOptions.Parser = templates.NewParser()
			execOptions.Logger = options.Logger
			execOptions.ResumeCfg = types.NewResumeCfg()
			store, err := loader.New(loader.NewConfig(options, execOptions.Catalog, execOptions))
			require.NoError(t, err)

			var mu sync.Mutex
			var resultIDs []string
			execOptions.Output.(*testutils.MockOutputWriter).WriteCallback = func(result *output.ResultEvent) {
				mu.Lock()
				defer mu.Unlock()
				resultIDs = append(resultIDs, result.TemplateID)
			}
			input := &contextargs.MetaInput{Input: server.URL}
			targets := provider.NewSimpleInputProviderWithUrls(options.ExecutionId, server.URL)
			loadOptions := Options{ExecuterOpts: execOptions, Store: store, Target: targets}
			tech, stats, err := loadTemplatesWithTagsWithStats(loadOptions, []string{root}, []string{"tech"}, true, false)
			require.NoError(t, err)
			wantRequests := 1
			if disabled {
				wantRequests = 2
			}
			require.Len(t, tech, wantRequests)
			require.Len(t, stats.PreClusterTemplates, 2)

			service := &Service{
				opts: execOptions, target: targets, ServiceOpts: loadOptions,
				templateDirs: []string{root}, techTemplates: tech, techTemplateStats: stats,
				hasResults: &atomic.Bool{}, totalGate: newTotalGate(execOptions.Progress),
				fingerprintCache: assetdomainfingerprint.FromEntries([]assetdomainfingerprint.Entry{{Target: server.URL}}),
			}
			mapped := service.mapTarget(input)
			require.EqualValues(t, wantRequests, fingerprintRequests.Load())
			require.True(t, service.hasResults.Load())
			require.ElementsMatch(t, []string{"alpha-detect", "second-detect"}, resultIDs)
			// Both fingerprint and vulnerability templates carry the mapped product tags.
			require.Len(t, mapped.finalTemplates, 2*wantRequests)
			require.EqualValues(t, 4, mapped.preClusterRequests)
			require.EqualValues(t, 4, mappedTemplateCount([]mappedTarget{mapped, mapped}))

			service.executeMappedTemplates(mapped)
			require.EqualValues(t, wantRequests, vulnerabilityRequests.Load())
			require.EqualValues(t, 2*wantRequests, fingerprintRequests.Load())
			require.ElementsMatch(t, []string{"alpha-detect", "second-detect", "alpha-detect", "second-detect", "alpha-vuln", "bravo-vuln"}, resultIDs)

			progress := &requestEstimateProgress{}
			execOptions.Progress = progress
			service.totalGate = newTotalGate(progress)
			service.setMappedRequestTotal([]mappedTarget{mapped})
			require.EqualValues(t, 3*wantRequests, progress.total)
			require.EqualValues(t, 6, progress.preCluster)
		})
	}
}
