package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"ManScan/pkg/input/provider"
	"ManScan/pkg/protocols/common/contextargs"
	"ManScan/pkg/protocols/common/protocolstate"
	"ManScan/pkg/utils"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/httpx/common/httpx"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
)

const assetDomainPreflightCacheEnv = "MANSCAN_ASSET_DOMAIN_PREFLIGHT_CACHE"

type preflightHTTPInputCache struct {
	Targets []struct {
		Target             string `json:"target"`
		ProbeDone          bool   `json:"probe_done"`
		FingerprintTargets []struct {
			Input string `json:"input"`
		} `json:"fingerprint_targets"`
	} `json:"targets"`
}

func loadPreflightHTTPInputs(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cache preflightHTTPInputCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	inputs := make(map[string]string, len(cache.Targets))
	for _, target := range cache.Targets {
		if !target.ProbeDone || target.Target == "" {
			continue
		}
		selectedURL := ""
		if len(target.FingerprintTargets) > 0 {
			selectedURL = target.FingerprintTargets[0].Input
			parsed, err := url.Parse(selectedURL)
			if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				continue
			}
		}
		inputs[strings.TrimSpace(target.Target)] = selectedURL
	}
	return inputs, nil
}

// initializeTemplatesHTTPInput initializes the http form of input
// for any loaded http templates if input is in non-standard format.
func (r *Runner) initializeTemplatesHTTPInput() (*hybrid.HybridMap, error) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary input file")
	}
	if r.inputProvider.InputType() == provider.MultiFormatInputProvider {
		// currently http probing for input mode types is not supported
		return hm, nil
	}
	preflightInputs := map[string]string(nil)
	if path := os.Getenv(assetDomainPreflightCacheEnv); path != "" {
		preflightInputs, err = loadPreflightHTTPInputs(path)
		if err != nil {
			r.Logger.Warning().Msgf("Could not load preflight HTTP input cache: %s", err)
		}
	}
	var count atomic.Int32
	var reused int
	var pending []string
	r.inputProvider.Iterate(func(value *contextargs.MetaInput) bool {
		if stringsutil.HasPrefixAny(value.Input, "http://", "https://") {
			return true
		}
		if selectedURL, ok := preflightInputs[value.Input]; ok {
			reused++
			if selectedURL != "" {
				_ = hm.Set(value.Input, []byte(selectedURL))
			}
			return true
		}
		pending = append(pending, value.Input)
		return true
	})
	if reused > 0 {
		r.Logger.Info().Msgf("Reused HTTP probe results for %d input hosts", reused)
	}
	if len(pending) == 0 {
		return hm, nil
	}
	r.Logger.Info().Msgf("Running httpx on %d input hosts without preflight results", len(pending))

	httpxOptions := httpx.DefaultOptions
	if r.options.AliveHttpProxy != "" {
		httpxOptions.Proxy = r.options.AliveHttpProxy
	} else if r.options.AliveSocksProxy != "" {
		httpxOptions.Proxy = r.options.AliveSocksProxy
	}
	httpxOptions.RetryMax = r.options.Retries
	httpxOptions.Timeout = time.Duration(r.options.Timeout) * time.Second

	dialers := protocolstate.GetDialersWithId(r.options.ExecutionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", r.options.ExecutionId)
	}

	httpxOptions.NetworkPolicy = dialers.NetworkPolicy
	httpxClient, err := httpx.New(&httpxOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create httpx client")
	}

	// Probe the non-standard URLs and store them in cache
	swg, err := syncutil.New(syncutil.WithSize(r.options.BulkSize))
	if err != nil {
		return nil, errors.Wrap(err, "could not create adaptive group")
	}
	for _, input := range pending {
		if r.options.ProbeConcurrency > 0 && swg.Size != r.options.ProbeConcurrency {
			if err := swg.Resize(context.Background(), r.options.ProbeConcurrency); err != nil {
				r.Logger.Error().Msgf("Could not resize workpool: %s\n", err)
			}
		}

		swg.Add()
		go func(input string) {
			defer swg.Done()

			if result := utils.ProbeURL(input, httpxClient); result != "" {
				count.Add(1)
				_ = hm.Set(input, []byte(result))
			}
		}(input)
	}
	swg.Wait()

	r.Logger.Info().Msgf("Found %d URL from httpx", count.Load())
	return hm, nil
}
