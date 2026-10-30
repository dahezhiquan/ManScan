package list

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"ManScan/pkg/protocols/common/contextargs"
	"ManScan/pkg/protocols/common/protocolstate"
	"ManScan/pkg/types"
	"ManScan/pkg/utils/expand"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/stretchr/testify/require"
)

func Test_expandCIDR(t *testing.T) {
	tests := []struct {
		cidr     string
		expected []string
	}{
		{
			cidr:     "173.0.84.0/30",
			expected: []string{"173.0.84.0", "173.0.84.1", "173.0.84.2", "173.0.84.3"},
		}, {
			cidr:     "104.154.124.0/29",
			expected: []string{"104.154.124.0", "104.154.124.1", "104.154.124.2", "104.154.124.3", "104.154.124.4", "104.154.124.5", "104.154.124.6", "104.154.124.7"},
		},
	}
	for _, tt := range tests {
		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.Nil(t, err, "could not create temporary input file")
		input := &ListInputProvider{hostMap: hm}

		ips := expand.CIDR(tt.cidr)
		input.addTargets("", ips)
		// scan
		got := []string{}
		input.hostMap.Scan(func(k, _ []byte) error {
			metainput := contextargs.NewMetaInput()
			if err := metainput.Unmarshal(string(k)); err != nil {
				return err
			}
			got = append(got, metainput.Input)
			return nil
		})
		require.ElementsMatch(t, tt.expected, got, "could not get correct cidrs")
		input.Close()
	}
}

func TestExcludeTargetsMatchesHostsPrecisely(t *testing.T) {
	tests := []struct {
		name      string
		exclude   string
		targets   []string
		remaining []string
	}{
		{"ipv4 without port", "10.107.70.20", []string{"http://10.107.70.20:8188", "http://10.107.70.201:8188", "http://10.107.70.20:9000"}, []string{"http://10.107.70.201:8188"}},
		{"ipv4 with port", "10.107.70.20:8188", []string{"http://10.107.70.20:8188", "http://10.107.70.20:9000", "http://10.107.70.201:8188"}, []string{"http://10.107.70.20:9000", "http://10.107.70.201:8188"}},
		{"domain without port", "example.com", []string{"https://EXAMPLE.com:443", "http://example.com:8080", "http://example.com.evil", "http://exampleXcom"}, []string{"http://example.com.evil", "http://exampleXcom"}},
		{"domain with port", "example.com:443", []string{"https://example.com:443", "http://example.com:8080", "http://example.com.evil:443"}, []string{"http://example.com:8080", "http://example.com.evil:443"}},
		{"url with path", "https://example.com:443/path", []string{"https://example.com:443/other", "http://example.com:8080"}, []string{"http://example.com:8080"}},
		{"url with query", "https://example.com:443/path?x=1", []string{"https://example.com:443/other", "http://example.com:8080", "http://example.com.evil:443"}, []string{"http://example.com:8080", "http://example.com.evil:443"}},
		{"ipv6", "[2001:db8::1]", []string{"http://[2001:0db8::1]:8080", "http://[2001:db8::10]:8080"}, []string{"http://[2001:db8::10]:8080"}},
		{"cidr", "10.107.70.0/24", []string{"http://10.107.70.201:8188", "http://10.107.71.201:8188"}, []string{"http://10.107.71.201:8188"}},
		{"explicit regex", `^api[0-9]+\.example\.com`, []string{"http://api1.example.com:80", "http://api.example.com:80"}, []string{"http://api.example.com:80"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hm, err := hybrid.New(hybrid.DefaultDiskOptions)
			require.NoError(t, err)
			input := &ListInputProvider{hostMap: hm, excludedHosts: make(map[string]struct{}), ipOptions: &ipOptions{IPV4: true}}
			t.Cleanup(input.Close)
			for _, target := range tt.targets {
				meta := contextargs.NewMetaInput()
				meta.Input = target
				input.setItem(meta)
			}
			if strings.Contains(tt.exclude, "/") && !strings.Contains(tt.exclude, "://") {
				input.removeTargets([]string{tt.exclude})
			} else {
				input.Del("", tt.exclude)
			}
			var remaining []string
			input.hostMap.Scan(func(k, _ []byte) error {
				var meta contextargs.MetaInput
				if err := meta.Unmarshal(string(k)); err != nil {
					return err
				}
				remaining = append(remaining, meta.Input)
				return nil
			})
			require.ElementsMatch(t, tt.remaining, remaining)
			require.Equal(t, int64(len(tt.targets)-len(tt.remaining)), input.excludedCount)
		})
	}
}

func TestExcludeTargetsDuringInitialization(t *testing.T) {
	options := types.DefaultOptions()
	options.IPVersion = []string{"4"}
	options.Targets = []string{"http://10.107.70.201:8188", "http://10.107.70.20:8188", "https://example.com.evil", "https://example.com"}
	options.ExcludeTargets = []string{"10.107.70.20", "example.com"}
	input, err := New(&Options{Options: options})
	require.NoError(t, err)
	t.Cleanup(input.Close)
	var remaining []string
	input.Iterate(func(meta *contextargs.MetaInput) bool {
		remaining = append(remaining, meta.Input)
		return true
	})
	require.ElementsMatch(t, []string{"http://10.107.70.201:8188", "https://example.com.evil"}, remaining)
	require.Equal(t, int64(2), input.excludedCount)
}

type mockDnsHandler struct{}

func (m *mockDnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeA:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("128.199.158.128"),
		})
	case dns.TypeAAAA:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		msg.Answer = append(msg.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("2400:6180:0:d0::91:1001"),
		})
	}
	_ = w.WriteMsg(&msg)
}

func Test_scanallips_normalizeStoreInputValue(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	resolverAddr := pc.LocalAddr().String()

	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn: pc,
		Handler:    &mockDnsHandler{},
		NotifyStartedFunc: func() {
			close(started)
		},
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown()
	})

	select {
	case <-started:
	case err := <-serveErr:
		require.NoError(t, err, "dns mock server failed to start")
	case <-time.After(5 * time.Second):
		require.Fail(t, "timed out waiting for dns mock server")
	}

	defaultOpts := types.DefaultOptions()
	defaultOpts.InternalResolversList = []string{resolverAddr}
	_ = protocolstate.Init(defaultOpts)
	type testcase struct {
		hostname string
		ipv4     bool
		ipv6     bool
		expected []string
	}
	tests := []testcase{
		{
			hostname: "scanme.sh",
			ipv4:     true,
			expected: []string{"128.199.158.128"},
		}, {
			hostname: "scanme.sh",
			ipv6:     true,
			expected: []string{"2400:6180:0:d0::91:1001"},
		},
	}
	// add extra edge cases
	urls := []string{
		"https://scanme.sh/",
		"http://scanme.sh",
		"https://scanme.sh:443/",
		"https://scanme.sh:443/somepath",
		"http://scanme.sh:80/?with=param",
		"scanme.sh/home",
		"scanme.sh",
	}
	resolvedIps := []string{"128.199.158.128", "2400:6180:0:d0::91:1001"}

	for _, v := range urls {
		tests = append(tests, testcase{
			hostname: v,
			ipv4:     true,
			ipv6:     true,
			expected: resolvedIps,
		})
	}
	for _, tt := range tests {
		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.Nil(t, err, "could not create temporary input file")
		input := &ListInputProvider{
			hostMap: hm,
			ipOptions: &ipOptions{
				ScanAllIPs: true,
				IPV4:       tt.ipv4,
				IPV6:       tt.ipv6,
			},
		}

		input.Set(defaultOpts.ExecutionId, tt.hostname)
		// scan
		got := []string{}
		input.hostMap.Scan(func(k, v []byte) error {
			metainput := contextargs.NewMetaInput()
			if err := metainput.Unmarshal(string(k)); err != nil {
				return err
			}
			got = append(got, metainput.CustomIP)
			return nil
		})
		require.ElementsMatchf(t, tt.expected, got, "could not get correct ips for hostname %v", tt.hostname)
		input.Close()
	}
}

func Test_expandASNInputValue(t *testing.T) {
	// skip this test if pdcp keys are not present
	h := pdcp.PDCPCredHandler{}
	creds, err := h.GetCreds()
	if err != nil || creds == nil || creds.APIKey == "" {
		t.Logf("Skipping asnmap test as pdcp keys are not present")
		t.SkipNow()
	}
	tests := []struct {
		asn                string
		expectedOutputFile string
	}{
		{
			asn:                "AS14421",
			expectedOutputFile: "tests/AS14421.txt",
		},
		{
			asn:                "AS134029",
			expectedOutputFile: "tests/AS134029.txt",
		},
	}
	for _, tt := range tests {
		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.Nil(t, err, "could not create temporary input file")
		input := &ListInputProvider{hostMap: hm}
		// get the IP addresses for ASN number
		ips := expand.ASN(tt.asn)
		input.addTargets("", ips)
		// scan the hmap
		got := []string{}
		input.hostMap.Scan(func(k, v []byte) error {
			metainput := contextargs.NewMetaInput()
			if err := metainput.Unmarshal(string(k)); err != nil {
				return err
			}
			got = append(got, metainput.Input)
			return nil
		})
		if len(got) == 0 {
			// asnmap server is down
			t.SkipNow()
		}
		// read the expected IPs from the file
		fileContent, err := os.ReadFile(tt.expectedOutputFile)
		require.Nil(t, err, "could not read the expectedOutputFile file")

		items := strings.Split(strings.ReplaceAll(string(fileContent), "\r\n", "\n"), "\n")

		require.ElementsMatch(t, items, got, "could not get correct ips")
	}
}
