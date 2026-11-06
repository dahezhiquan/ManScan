package runner

import (
	"os"
	"path/filepath"
	"testing"

	"ManScan/pkg/input/provider"
	"ManScan/pkg/protocols/common/contextargs"
	"ManScan/pkg/types"
	"github.com/projectdiscovery/gologger"
)

type preflightInputProvider struct {
	provider.InputProvider
	inputs []string
}

func (p preflightInputProvider) InputType() string {
	return provider.ListInputProvider
}

func (p preflightInputProvider) Iterate(callback func(*contextargs.MetaInput) bool) {
	for _, input := range p.inputs {
		value := contextargs.NewMetaInput()
		value.Input = input
		if !callback(value) {
			return
		}
	}
}

func TestInitializeTemplatesHTTPInputReusesPreflightResults(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "asset-domain-preflight.json")
	cache := `{"targets":[{"target":"alive.example","probe_done":true,"fingerprint_targets":[{"Input":"http://alive.example"}]},{"target":"down.example","probe_done":true,"fingerprint_targets":[]}]}`
	if err := os.WriteFile(cachePath, []byte(cache), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(assetDomainPreflightCacheEnv, cachePath)
	runner := &Runner{
		inputProvider: preflightInputProvider{inputs: []string{"alive.example", "down.example"}},
		options:       &types.Options{},
		Logger:        gologger.DefaultLogger,
	}
	inputs, err := runner.initializeTemplatesHTTPInput()
	if err != nil {
		t.Fatal(err)
	}
	defer inputs.Close()
	if got, ok := inputs.Get("alive.example"); !ok || string(got) != "http://alive.example" {
		t.Fatalf("alive target URL = %q, found = %v", got, ok)
	}
	if _, ok := inputs.Get("down.example"); ok {
		t.Fatal("unresponsive target must not get a URL")
	}
}

func TestLoadPreflightHTTPInputsFallsBackForIncompleteEntries(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "asset-domain-preflight.json")
	cache := `{"targets":[{"target":"done.example","probe_done":true,"fingerprint_targets":[{"Input":"https://done.example"}]},{"target":"pending.example","probe_done":false},{"target":"invalid.example","probe_done":true,"fingerprint_targets":[{"Input":"file:///tmp/input"}]}]}`
	if err := os.WriteFile(cachePath, []byte(cache), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs, err := loadPreflightHTTPInputs(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if inputs["done.example"] != "https://done.example" {
		t.Fatalf("cached URL = %q", inputs["done.example"])
	}
	for _, target := range []string{"pending.example", "invalid.example"} {
		if _, ok := inputs[target]; ok {
			t.Fatalf("%s must fall back to normal probing", target)
		}
	}
}
