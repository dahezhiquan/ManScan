package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"ManScan/server/internal/model/dto"
)

func TestCanonicalAssetDomainFromURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "https default port",
			url:  "https://App.Example.com/login",
			want: "app.example.com:443",
		},
		{
			name: "http default port",
			url:  "http://app.example.com",
			want: "app.example.com:80",
		},
		{
			name: "explicit port",
			url:  "https://app.example.com:8443/path",
			want: "app.example.com:8443",
		},
		{
			name: "ip with explicit port",
			url:  "http://10.107.71.65:8889/",
			want: "10.107.71.65:8889",
		},
		{
			name: "ip with default https port",
			url:  "https://10.107.71.65/",
			want: "10.107.71.65:443",
		},
		{
			name: "invalid port",
			url:  "https://app.example.com:99999",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := canonicalAssetDomainFromURL(tc.url); got != tc.want {
				t.Fatalf("canonicalAssetDomainFromURL(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

func TestProbeAssetDomainLivenessUsesHTTPXProbe(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	target := "http://localhost:" + parsed.Port()

	result, err := probeAssetDomainLiveness(context.Background(), dto.CreateScanTaskRequest{
		ProbeConcurrency: 2,
		Timeout:          3,
	}, []string{target, target, "http://192.0.2.10"})
	if err != nil {
		t.Fatalf("probeAssetDomainLiveness() error = %v", err)
	}

	want := "localhost:" + parsed.Port()
	if len(result.AliveDomains) != 1 || result.AliveDomains[0] != want {
		t.Fatalf("AliveDomains = %v, want [%s]", result.AliveDomains, want)
	}
	if len(result.CheckedDomains) != 2 {
		t.Fatalf("CheckedDomains = %v, want localhost and 192.0.2.10", result.CheckedDomains)
	}
}
