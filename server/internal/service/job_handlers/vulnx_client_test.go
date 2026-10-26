package job_handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVulnxClientFetchMapsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/vulnerability/CVE-2024-3094" || r.Header.Get("X-Api-Key") != "test-key" {
			t.Fatalf("request = %s, api key = %q", r.URL.Path, r.Header.Get("X-Api-Key"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"cve_id":"CVE-2024-3094","doc_type":"cve_template","created_at":"2024-03-29T17:15:21Z","updated_at":"2026-10-25T16:03:56.02Z","cvss_metrics":"CVSS:3.1/AV:N","cvss_score":10,"cwe":["CWE-506"],"description":"description","epss_percentile":0.99804,"epss_score":0.909,"exposure":{"max_hosts":12,"min_hosts":2,"values":[{"id":"tukaani:xz","max_hosts":5,"min_hosts":3,"shodan":{"max_hosts":5,"min_hosts":3,"queries":["product:\"xz\""]}}]},"h1":{"rank":7,"reports":11},"impact":"impact","is_oss":true,"is_poc":true,"is_remote":true,"is_template":true,"name":"xz - Code Injection","poc_count":1,"poc_first_seen":"2024-03-29T17:03:01Z","pocs":[{"added_at":"2024-03-29T17:03:01Z","source":"nvd","url":"https://example.test/poc"}],"remediation":"upgrade","severity":"critical","vuln_status":"confirmed","vulnerability_impact":["remote_code_execution"],"vulnerability_type":"backdoor","affected_products":[{"cpe":["cpe:2.3:a:tukaani:xz:*"],"deployment_model":"dependency","product":"xz","summary":"summary","vendor":"tukaani"}],"citations":[{"added_at":"2024-03-29T17:03:01Z","source":"nvd","url":"https://example.test/advisory"}]}}`))
	}))
	defer server.Close()

	client := NewVulnxClient("test-key")
	client.BaseURL = server.URL
	bundle, err := client.Fetch(context.Background(), "CVE-2024-3094")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Record.Category == nil || *bundle.Record.Category != "cve" || bundle.Record.MaxHosts == nil || *bundle.Record.MaxHosts != 12 || bundle.Record.MinHosts == nil || *bundle.Record.MinHosts != 2 || bundle.Record.VulnerabilityID != "CVE-2024-3094" || bundle.Record.H1Rank == nil || *bundle.Record.H1Rank != 7 || bundle.Record.H1Reports == nil || *bundle.Record.H1Reports != 11 {
		t.Fatalf("record mapping = %+v", bundle.Record)
	}
	if len(bundle.Components) != 1 || bundle.Components[0].Product != "xz" || len(bundle.Articles) != 1 || len(bundle.POCs) != 1 || len(bundle.ShodanItems) != 1 || bundle.ShodanItems[0].ProductName == nil || *bundle.ShodanItems[0].ProductName != "tukaani:xz" {
		t.Fatalf("related mapping = %+v", bundle)
	}
}

func TestVulnxClientRejectsInvalidCVEID(t *testing.T) {
	client := NewVulnxClient("")
	if _, err := client.Fetch(context.Background(), "CVE-2024/3094"); err == nil || !strings.Contains(err.Error(), "格式不合法") {
		t.Fatalf("Fetch() error = %v", err)
	}
}

func TestVulnxClientPreservesMissingNullableFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"cve_id":"CVE-2024-3094","citations":[{"url":"https://example.test/advisory"}],"affected_products":[{"product":"xz"}],"pocs":[{"url":"https://example.test/poc"}],"exposure":{"values":[{"id":"tukaani:xz","shodan":{"queries":[]}}]}}}`))
	}))
	defer server.Close()

	client := NewVulnxClient("")
	client.BaseURL = server.URL
	bundle, err := client.Fetch(context.Background(), "CVE-2024-3094")
	if err != nil {
		t.Fatal(err)
	}
	record := bundle.Record
	if record.AgeInDays != nil || record.Category != nil || record.CreatedAt != nil || record.UpdatedAt != nil || record.MaxHosts != nil || record.IsPOC != nil || record.POCCount != nil || record.Severity != nil {
		t.Fatalf("missing record fields = %+v, want nil pointers", record)
	}
	if len(bundle.Articles) != 1 || bundle.Articles[0].AddedAt != nil || bundle.Articles[0].Source != nil || len(bundle.POCs) != 1 || bundle.POCs[0].AddedAt != nil || bundle.POCs[0].Source != nil || bundle.Components[0].DeploymentModel != nil || bundle.ShodanItems[0].MaxHosts != nil || bundle.ShodanItems[0].MinHosts != nil {
		t.Fatalf("missing related fields = %+v, want nil pointers", bundle)
	}
}
