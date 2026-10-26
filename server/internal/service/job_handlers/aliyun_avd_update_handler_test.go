package job_handlers

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseAVDListFiltersNoCVE(t *testing.T) {
	page := []byte(`<table><tbody>
<tr><td><a href="/detail?id=AVD-2026-1">AVD-2026-1</a></td><td>Has CVE CVE-2026-10</td><td>CWE-1</td><td>2026-01-01</td><td><button title="CVE-2026-10">CVE</button></td></tr>
<tr><td><a href="/detail?id=AVD-2026-2">AVD-2026-2</a></td><td>No CVE vuln</td><td>未定义</td><td>2026-02-01</td><td><button title="无CVE">CVE</button><button title="POC 已公开">PoC</button></td></tr>
</tbody></table>`)
	items, err := parseAVDList(page)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || isNoCVEItem(items[0]) || !isNoCVEItem(items[1]) {
		t.Fatalf("parsed list items = %+v", items)
	}
	if items[1].DetailURL != aliyunAVDBaseURL+"/detail?id=AVD-2026-2" || len(items[1].Statuses) != 2 {
		t.Fatalf("no-CVE item = %+v", items[1])
	}
}

func TestParseAVDDetailCapturesRiskAndAffectedSoftware(t *testing.T) {
	body := []byte(`<h5 class="header__title"><span class="badge btn-warning">高危</span><span class="header__title__text">Example</span></h5>
<div class="metric"><p class="metric-label">CVE编号</p><div class="metric-value">暂无</div></div>
<div class="metric"><p class="metric-label">披露时间</p><div class="metric-value">2026-02-01</div></div>
<h6>漏洞描述</h6><div>description</div><h6>解决建议</h6><div>upgrade</div>
<div class="reference"><table><tbody><tr><td><a href="https://example.test/advisory">ref</a></td></tr></tbody></table></div>
<div class="cvss-breakdown__score">8.2</div><li class="cvss-breakdown__item"><div class="cvss-breakdown__title">攻击路径</div><div class="cvss-breakdown__desc">远程</div></li>
<h6>受影响软件情况</h6><div><table><tbody><tr><td class="bg-light">系统</td><td class="bg-light">vendor</td><td class="bg-light">product</td><td class="bg-light">*</td><td class="bg-light">Up to 1.0</td></tr></tbody></table></div>
<div class="card--sidebar"><div class="card__content">阿里云安全产品覆盖情况</div><div><button title="已支持">云安全中心</button><button class="disabled">WAF</button></div></div>`)
	item := AVDListItem{VulnerabilityID: "AVD-2026-2", Title: "Example", DetailURL: aliyunAVDBaseURL + "/detail?id=AVD-2026-2"}
	vuln, err := parseAVDDetail(body, item)
	if err != nil {
		t.Fatal(err)
	}
	if vuln.Severity != "高危" || vuln.Disclosure != "2026-02-01" || vuln.Description != "description" || vuln.Remediation != "upgrade" {
		t.Fatalf("vulnerability fields = %+v", vuln)
	}
	if vuln.AliyunScore == nil || *vuln.AliyunScore != 8.2 || vuln.RiskMetrics.AttackPath != "远程" || len(vuln.References) != 1 || len(vuln.AffectedSoftware) != 1 || len(vuln.SecurityCoverage) != 2 || !vuln.SecurityCoverage[0].Supported || vuln.SecurityCoverage[1].Supported {
		t.Fatalf("extended fields = %+v", vuln)
	}
}

func TestAVDHandlerWritesOutputWithoutDatabase(t *testing.T) {
	root := t.TempDir()
	collection := &AVDCollection{FetchedAt: time.Now(), ListPages: 1, ListedCount: 1, NoCVECandidateCount: 1, Vulnerabilities: []AVDVulnerability{{VulnerabilityID: "AVD-2026-2", Title: "Example", References: []string{"https://example.test"}}}}
	path := avdOutputPath(root)
	if err := writeAVDCollection(path, collection); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AVDCollection
	if err := json.Unmarshal(data, &decoded); err != nil || len(decoded.Vulnerabilities) != 1 {
		t.Fatalf("decoded output = %+v, err = %v", decoded, err)
	}
	if strings.Contains(string(data), "manscan_vulnerability_intelligence_records") {
		t.Fatal("output unexpectedly references a database table")
	}
}

func TestAVDBundleUsesConfirmedFieldMapping(t *testing.T) {
	score := 8.3
	bundle, err := avdVulnerabilityBundle(&AVDVulnerability{
		VulnerabilityID: "AVD-2026-1911719",
		Title:           "Redis blocked-client 远程代码执行漏洞",
		Severity:        "高危",
		ExploitStatus:   "POC 已公开",
		PatchStatus:     "官方补丁",
		Disclosure:      "2026-08-19",
		Description:     "漏洞描述",
		Remediation:     "解决建议",
		References:      []string{"https://example.test/advisory"},
		AliyunScore:     &score,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := bundle.Record
	if record.Source != "avd" || record.VulnerabilityID != "AVD-2026-1911719" || record.Severity == nil || *record.Severity != "high" || record.IsPOC == nil || !*record.IsPOC {
		t.Fatalf("mapped record = %+v", record)
	}
	if record.Category == nil || *record.Category != "non-cve" || record.CreatedAt == nil || record.CreatedAt.Format("2006-01-02") != "2026-08-19" || record.UpdatedAt != nil || record.VulnerabilityImpact != nil {
		t.Fatalf("record timestamps/impact = %+v", record)
	}
	if record.CVSSScore == nil || *record.CVSSScore != score || len(bundle.Articles) != 1 || bundle.Articles[0].Source == nil || *bundle.Articles[0].Source != "avd" || bundle.Articles[0].URL != "https://example.test/advisory" || bundle.Articles[0].AddedAt != nil {
		t.Fatalf("mapped articles/score = %+v / %+v", bundle.Articles, record.CVSSScore)
	}
	if len(bundle.Components) != 0 || len(bundle.POCs) != 0 || len(bundle.ShodanItems) != 0 {
		t.Fatalf("unexpected related tables mapped: %+v", bundle)
	}
}

func TestAVDBundleAllowsMissingNullableDisclosureTime(t *testing.T) {
	bundle, err := avdVulnerabilityBundle(&AVDVulnerability{VulnerabilityID: "AVD-2026-1911719", Title: "Vulnerability"})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Record.CreatedAt != nil || bundle.Record.UpdatedAt != nil {
		t.Fatalf("record timestamps = created:%v updated:%v, want nil", bundle.Record.CreatedAt, bundle.Record.UpdatedAt)
	}
}

func TestAVDSeverityValues(t *testing.T) {
	for input, want := range map[string]string{"严重": "critical", "高危": "high", "低危": "low", "中危": "medium", "other": "none"} {
		if got := avdSeverity(input); got != want {
			t.Errorf("avdSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAVDURLValidationRejectsUntrustedHosts(t *testing.T) {
	for _, raw := range []string{"http://avd.aliyun.com/high-risk/list", "https://example.com/", "https://avd.aliyun.com.evil.test/"} {
		u, err := resolveAVDURL(raw)
		if err == nil || u != "" {
			t.Fatalf("resolveAVDURL(%q) = %q, %v; expected rejection", raw, u, err)
		}
	}
}
