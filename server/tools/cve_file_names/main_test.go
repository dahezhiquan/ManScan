package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func writeTestResponse(t *testing.T, w http.ResponseWriter, payload string) {
	t.Helper()
	if _, err := fmt.Fprint(w, payload); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func TestListCVEFileNames(t *testing.T) {
	responses := map[string]string{
		"main":                   `{"tree":[{"path":"cves","type":"tree","sha":"cves-sha"},{"path":"README.md","type":"blob","sha":"readme"}]}`,
		"cves-sha?recursive=1":   `{"truncated":true,"tree":[{"path":"CVE-1999-9999.json","type":"blob"}]}`,
		"cves-sha":               `{"tree":[{"path":"2024","type":"tree","sha":"year-sha"},{"path":"CVE-2020-0003.json","type":"blob","sha":"duplicate-sha"}]}`,
		"year-sha?recursive=1":   `{"truncated":true,"tree":[]}`,
		"year-sha":               `{"tree":[{"path":"0xxx","type":"tree","sha":"bucket-sha"}]}`,
		"bucket-sha?recursive=1": `{"tree":[{"path":"CVE-2024-0002.json","type":"blob","sha":"one"},{"path":"nested/CVE-2024-0001.json","type":"blob","sha":"two"},{"path":"nested/CVE-2020-0003.json","type":"blob"},{"path":"nested","type":"tree","sha":"unused"},{"path":"not-a-cve.json","type":"blob","sha":"three"},{"path":"CVE-2024-0001.txt","type":"blob","sha":"four"},{"path":"CVE-2024-9999.json","type":"commit"}]}`,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" || r.Method != http.MethodGet {
			t.Errorf("unexpected method or authorization header")
		}
		const prefix = "/repos/CVEProject/cvelistV5/git/trees/"
		if !strings.HasPrefix(r.RequestURI, prefix) {
			http.NotFound(w, r)
			return
		}
		payload, ok := responses[strings.TrimPrefix(r.RequestURI, prefix)]
		if !ok {
			t.Errorf("unexpected request %s", r.RequestURI)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeTestResponse(t, w, payload)
	}))
	defer server.Close()

	client := NewGitHubTreeClient("test-token")
	client.BaseURL = server.URL
	got, err := client.ListCVEFileNames(context.Background(), "main")
	if err != nil {
		t.Fatalf("ListCVEFileNames returned error: %v", err)
	}
	want := []string{"CVE-2020-0003", "CVE-2024-0001", "CVE-2024-0002"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListCVEFileNames() = %#v, want %#v", got, want)
	}
}

func TestListCVEFileNamesRejectsTruncatedTree(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/CVEProject/cvelistV5/git/trees/main" {
			writeTestResponse(t, w, `{"tree":[{"path":"cves","type":"tree","sha":"cves-sha"}]}`)
			return
		}
		writeTestResponse(t, w, `{"truncated":true,"tree":[]}`)
	}))
	defer server.Close()

	client := NewGitHubTreeClient("")
	client.BaseURL = server.URL
	if names, err := client.ListCVEFileNames(context.Background(), "main"); err == nil || names != nil {
		t.Fatalf("ListCVEFileNames() = %v, %v; want no partial names and a truncation error", names, err)
	}
}

func TestListCVEFileNamesRequiresRef(t *testing.T) {
	client := NewGitHubTreeClient("")
	if _, err := client.ListCVEFileNames(context.Background(), " "); err == nil {
		t.Fatal("ListCVEFileNames() returned nil error for an empty ref")
	}
}

func TestListCVEFileNamesErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"root truncated", 200, `{"truncated":true,"tree":[]}`, "root tree response is truncated"},
		{"missing directory", 200, `{"tree":[]}`, "does not contain a cves directory"},
		{"invalid JSON", 200, `not json`, "decode GitHub tree response"},
		{"missing tree", 200, `{}`, "missing the tree array"},
		{"forbidden", 403, `test-token`, "GITHUB_TOKEN"},
		{"rate limited", 429, `test-token`, "rate limited"},
		{"unauthorized", 401, `test-token`, "HTTP 401"},
		{"server error", 500, `test-token`, "HTTP 500"},
		{"redirect", 302, `test-token`, "HTTP 302"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "https://example.invalid/")
				w.WriteHeader(tt.status)
				writeTestResponse(t, w, tt.body)
			}))
			defer server.Close()
			client := NewGitHubTreeClient("test-token")
			client.BaseURL = server.URL
			names, err := client.ListCVEFileNames(context.Background(), "main")
			if names != nil || err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, %v; want no names and error containing %q", names, err, tt.want)
			}
			if strings.Contains(err.Error(), "test-token") {
				t.Fatal("error contains response body/token")
			}
		})
	}
}

func TestListCVEFileNamesCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewGitHubTreeClient("").ListCVEFileNames(ctx, "main")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestListCVEFileNamesEmptyDirectory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{"tree":[]}`
		if strings.HasSuffix(r.URL.Path, "/main") {
			body = `{"tree":[{"path":"cves","type":"tree","sha":"cves-sha"}]}`
		}
		writeTestResponse(t, w, body)
	}))
	defer server.Close()
	client := NewGitHubTreeClient("")
	client.BaseURL = server.URL
	names, err := client.ListCVEFileNames(context.Background(), "main")
	if err != nil || len(names) != 0 {
		t.Fatalf("got %v, %v; want an empty list", names, err)
	}
}
