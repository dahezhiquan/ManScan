package job_handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/goja"
)

const (
	aliyunAVDHost          = "avd.aliyun.com"
	aliyunAVDBaseURL       = "https://avd.aliyun.com"
	aliyunAVDListPath      = "/high-risk/list"
	aliyunAVDMaxBody       = 16 << 20
	aliyunAVDMaxScript     = 256 << 10
	aliyunAVDMaxPages      = 10000
	aliyunAVDMaxRetries    = 3
	aliyunAVDDefaultDelay  = 250 * time.Millisecond
	aliyunAVDScriptTimeout = 3 * time.Second
)

var (
	aliyunAVDScriptPattern = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	aliyunAVDCVEPattern    = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]+\b`)
	aliyunAVDIDPattern     = regexp.MustCompile(`^AVD-[0-9]{4}-[0-9]+$`)
	aliyunAVDCWEPattern    = regexp.MustCompile(`(?i)^CWE-[0-9]+$`)
)

// AVDListItem 是阿里云高危列表页的一行。
type AVDListItem struct {
	VulnerabilityID   string   `json:"vulnerability_id"`
	Title             string   `json:"title"`
	VulnerabilityType string   `json:"vulnerability_type"`
	Disclosure        string   `json:"disclosure"`
	Statuses          []string `json:"statuses"`
	DetailURL         string   `json:"detail_url"`
}

// AVDVulnerability 是阿里云详情页可见的完整结构化快照。
type AVDVulnerability struct {
	VulnerabilityID  string                `json:"vulnerability_id"`
	Title            string                `json:"title"`
	Severity         string                `json:"severity"`
	CVE              string                `json:"cve,omitempty"`
	ExploitStatus    string                `json:"exploit_status,omitempty"`
	PatchStatus      string                `json:"patch_status,omitempty"`
	Disclosure       string                `json:"disclosure,omitempty"`
	Description      string                `json:"description,omitempty"`
	Remediation      string                `json:"remediation,omitempty"`
	References       []string              `json:"references"`
	AliyunScore      *float64              `json:"aliyun_score,omitempty"`
	RiskMetrics      AVDRiskMetrics        `json:"risk_metrics"`
	CWEs             []AVDCWE              `json:"cwes"`
	AffectedSoftware []AVDAffectedSoftware `json:"affected_software"`
	SecurityCoverage []AVDSecurityCoverage `json:"security_coverage"`
	ListMetadata     AVDListItem           `json:"list_metadata"`
	SourceURL        string                `json:"source_url"`
	FetchedAt        time.Time             `json:"fetched_at"`
}

type AVDRiskMetrics struct {
	AttackPath         string `json:"attack_path,omitempty"`
	AttackComplexity   string `json:"attack_complexity,omitempty"`
	PrivilegesRequired string `json:"privileges_required,omitempty"`
	Scope              string `json:"scope,omitempty"`
	ExploitMaturity    string `json:"exploit_maturity,omitempty"`
	PatchStatus        string `json:"patch_status,omitempty"`
	Confidentiality    string `json:"confidentiality,omitempty"`
	Integrity          string `json:"integrity,omitempty"`
	ServerImpact       string `json:"server_impact,omitempty"`
	InternetCount      string `json:"internet_count,omitempty"`
}

type AVDCWE struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type AVDAffectedSoftware struct {
	Type    string `json:"type,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Impact  string `json:"impact,omitempty"`
}

type AVDSecurityCoverage struct {
	Name        string `json:"name"`
	Supported   bool   `json:"supported"`
	Description string `json:"description,omitempty"`
}

type AVDCollection struct {
	FetchedAt           time.Time          `json:"fetched_at"`
	ListPages           int                `json:"list_pages"`
	ListedCount         int                `json:"listed_count"`
	NoCVECandidateCount int                `json:"no_cve_candidate_count"`
	Vulnerabilities     []AVDVulnerability `json:"vulnerabilities"`
	Errors              []string           `json:"errors,omitempty"`
}

// AVDProgressFunc reports progress after a list page and its candidate details
// have been processed.
type AVDProgressFunc func(context.Context, int64, int64, string, string) error

// AVDClient 顺序访问阿里云 AVD 页面，避免并发请求放大 WAF 风险。
type AVDClient struct {
	httpClient   *http.Client
	requestDelay time.Duration
	maxPages     int
	progress     AVDProgressFunc
}

func NewAVDClient(requestDelay time.Duration, maxPages int) *AVDClient {
	if requestDelay < 0 {
		requestDelay = aliyunAVDDefaultDelay
	}
	if maxPages <= 0 || maxPages > aliyunAVDMaxPages {
		maxPages = aliyunAVDMaxPages
	}
	jar, _ := cookiejar.New(nil)
	return &AVDClient{
		httpClient: &http.Client{
			Jar:     jar,
			Timeout: 45 * time.Second,
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if err := validateAVDURL(req.URL); err != nil {
					return err
				}
				return nil
			},
		},
		requestDelay: requestDelay,
		maxPages:     maxPages,
	}
}

func (c *AVDClient) CollectNoCVE(ctx context.Context) (*AVDCollection, error) {
	result := &AVDCollection{FetchedAt: time.Now().UTC(), Vulnerabilities: make([]AVDVulnerability, 0)}
	seen := make(map[string]struct{})
	exhausted := false
	for page := 1; page <= c.maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		body, err := c.fetch(ctx, fmt.Sprintf("%s%s?page=%d", aliyunAVDBaseURL, aliyunAVDListPath, page))
		if err != nil {
			return result, fmt.Errorf("获取阿里云高危列表第 %d 页失败: %w", page, err)
		}
		items, err := parseAVDList(body)
		if err != nil {
			return result, fmt.Errorf("解析阿里云高危列表第 %d 页失败: %w", page, err)
		}
		if len(items) == 0 {
			exhausted = true
			if c.progress != nil {
				message := fmt.Sprintf("已处理列表第 %d 页，未发现更多条目", page)
				if err := c.progress(ctx, int64(page), int64(c.maxPages), "fetching", message); err != nil {
					return result, err
				}
			}
			break
		}
		result.ListPages = page
		result.ListedCount += len(items)
		for _, item := range items {
			if !isNoCVEItem(item) {
				continue
			}
			if _, ok := seen[item.VulnerabilityID]; ok {
				continue
			}
			seen[item.VulnerabilityID] = struct{}{}
			result.NoCVECandidateCount++
			body, fetchErr := c.fetch(ctx, item.DetailURL)
			if fetchErr != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", item.VulnerabilityID, fetchErr))
				continue
			}
			vuln, parseErr := parseAVDDetail(body, item)
			if parseErr != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", item.VulnerabilityID, parseErr))
				continue
			}
			result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
		}
		if c.progress != nil {
			message := fmt.Sprintf("已处理列表第 %d 页，筛出 %d 条无 CVE 候选，成功获取 %d 条详情", page, result.NoCVECandidateCount, len(result.Vulnerabilities))
			if err := c.progress(ctx, int64(page), int64(c.maxPages), "fetching", message); err != nil {
				return result, err
			}
		}
	}
	if !exhausted && result.ListPages == c.maxPages {
		return result, errors.New("阿里云高危列表超过最大页数限制")
	}
	return result, nil
}

func isNoCVEItem(item AVDListItem) bool {
	for _, status := range item.Statuses {
		if strings.Contains(status, "无CVE") {
			return true
		}
		if aliyunAVDCVEPattern.MatchString(status) {
			return false
		}
	}
	return !aliyunAVDCVEPattern.MatchString(item.Title)
}

func (c *AVDClient) fetch(ctx context.Context, target string) ([]byte, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if err := validateAVDURL(u); err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < aliyunAVDMaxRetries; attempt++ {
		if err := sleepContext(ctx, c.requestDelay); err != nil {
			return nil, err
		}
		body, challenge, err := c.get(ctx, u.String())
		if err == nil && !challenge {
			return body, nil
		}
		if err != nil {
			lastErr = err
		} else if challenge {
			generated, solveErr := solveAVDWAF(u.String(), body)
			if solveErr != nil {
				lastErr = solveErr
			} else if generated != u.String() {
				if err := sleepContext(ctx, c.requestDelay); err != nil {
					return nil, err
				}
				body, challenge, err = c.get(ctx, generated)
				if err == nil && !challenge {
					return body, nil
				}
				if err != nil {
					lastErr = err
				} else {
					lastErr = errors.New("阿里云 WAF 校验后仍返回挑战页")
				}
			} else {
				lastErr = errors.New("阿里云 WAF 未生成有效校验 URL")
			}
		}
		if err := sleepContext(ctx, time.Duration(attempt+1)*time.Second); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *AVDClient) get(ctx context.Context, target string) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, aliyunAVDMaxBody+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > aliyunAVDMaxBody {
		return nil, false, errors.New("阿里云页面超过响应大小限制")
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, false, fmt.Errorf("阿里云响应状态码 %d", resp.StatusCode)
	}
	return body, bytes.Contains(body, []byte("renderData")), nil
}

func solveAVDWAF(target string, body []byte) (generated string, err error) {
	matches := aliyunAVDScriptPattern.FindSubmatch(body)
	if len(matches) != 2 {
		return "", errors.New("阿里云 WAF 挑战页缺少脚本")
	}
	if len(matches[1]) > aliyunAVDMaxScript {
		return "", errors.New("阿里云 WAF 挑战脚本超过大小限制")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("执行阿里云 WAF 脚本失败: %v", recovered)
		}
	}()
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	location := map[string]interface{}{"href": target}
	parser := func() map[string]interface{} {
		protocol := u.Scheme + ":"
		search := "?" + u.RawQuery
		parsed := map[string]interface{}{"protocol": protocol, "host": u.Host, "hostname": u.Hostname(), "port": u.Port(), "pathname": u.Path, "search": search, "hash": u.Fragment, "url": u.String(), "href": u.String()}
		firstChild := make(map[string]interface{}, len(parsed))
		for key, value := range parsed {
			firstChild[key] = value
		}
		parsed["firstChild"] = firstChild
		return parsed
	}
	document := map[string]interface{}{"cookie": "", "location": location, "createElement": func(...interface{}) map[string]interface{} { return parser() }}
	window := map[string]interface{}{"navigator": map[string]interface{}{"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"}, "location": location, "document": document}
	vm := goja.New()
	_ = vm.Set("window", window)
	_ = vm.Set("document", document)
	_ = vm.Set("location", location)
	timer := time.AfterFunc(aliyunAVDScriptTimeout, func() { vm.Interrupt("阿里云 WAF 脚本执行超时") })
	_, err = vm.RunScript("aliyun-avd-waf.js", string(matches[1]))
	timer.Stop()
	vm.ClearInterrupt()
	if err != nil {
		return "", err
	}
	generated, _ = location["href"].(string)
	if generated == "" {
		return "", errors.New("阿里云 WAF 脚本未生成 URL")
	}
	parsed, err := url.Parse(generated)
	if err != nil {
		return "", err
	}
	if err := validateAVDURL(parsed); err != nil {
		return "", err
	}
	return generated, nil
}

func parseAVDList(body []byte) ([]AVDListItem, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	items := make([]AVDListItem, 0)
	doc.Find("tbody > tr").Each(func(_ int, row *goquery.Selection) {
		link := row.Find("td > a[href]").First()
		href, ok := link.Attr("href")
		if !ok {
			return
		}
		detail, err := resolveAVDURL(href)
		if err != nil {
			return
		}
		id := cleanText(link.Text())
		if !aliyunAVDIDPattern.MatchString(id) {
			return
		}
		cells := row.Find("td")
		if cells.Length() < 5 {
			return
		}
		statuses := make([]string, 0)
		cells.Eq(4).Find("[title]").Each(func(_ int, item *goquery.Selection) {
			if value, exists := item.Attr("title"); exists && cleanText(value) != "" {
				statuses = append(statuses, cleanText(value))
			}
		})
		items = append(items, AVDListItem{VulnerabilityID: id, Title: cleanText(cells.Eq(1).Text()), VulnerabilityType: cleanText(cells.Eq(2).Text()), Disclosure: cleanText(cells.Eq(3).Text()), Statuses: statuses, DetailURL: detail})
	})
	if len(items) == 0 {
		pageText := cleanText(doc.Text())
		if strings.Contains(pageText, "请求错误") || !strings.Contains(pageText, "阿里云漏洞库") {
			return nil, errors.New("响应不是有效的阿里云漏洞列表页")
		}
	}
	return items, nil
}

func parseAVDDetail(body []byte, item AVDListItem) (*AVDVulnerability, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	header := doc.Find("h5.header__title").First()
	if header.Length() == 0 {
		return nil, errors.New("详情页缺少标题")
	}
	vuln := &AVDVulnerability{VulnerabilityID: item.VulnerabilityID, Title: cleanText(header.Find(".header__title__text").Text()), Severity: cleanText(header.Find(".badge").First().Text()), References: make([]string, 0), CWEs: make([]AVDCWE, 0), AffectedSoftware: make([]AVDAffectedSoftware, 0), SecurityCoverage: make([]AVDSecurityCoverage, 0), ListMetadata: item, SourceURL: item.DetailURL, FetchedAt: time.Now().UTC()}
	doc.Find("div.metric").Each(func(_ int, metric *goquery.Selection) {
		label, value := cleanText(metric.Find(".metric-label").Text()), cleanText(metric.Find(".metric-value").Text())
		switch {
		case strings.HasPrefix(label, "CVE"):
			vuln.CVE = value
		case strings.HasPrefix(label, "利用情况"):
			vuln.ExploitStatus = value
		case strings.HasPrefix(label, "补丁情况"):
			vuln.PatchStatus = value
		case strings.HasSuffix(label, "披露时间"):
			vuln.Disclosure = value
		}
	})
	if !aliyunAVDCVEPattern.MatchString(vuln.CVE) {
		vuln.CVE = ""
	}
	vuln.Description = avdSectionText(doc, "漏洞描述")
	vuln.Remediation = avdSectionText(doc, "解决建议")
	doc.Find("div.reference tbody tr a[href]").Each(func(_ int, link *goquery.Selection) {
		if href, ok := link.Attr("href"); ok && strings.HasPrefix(strings.ToLower(strings.TrimSpace(href)), "http") {
			vuln.References = append(vuln.References, strings.TrimSpace(html.UnescapeString(href)))
		}
	})
	if score := cleanText(doc.Find(".cvss-breakdown__score").First().Text()); score != "" {
		if value, parseErr := strconv.ParseFloat(score, 64); parseErr == nil {
			vuln.AliyunScore = &value
		}
	}
	doc.Find(".cvss-breakdown__item").Each(func(_ int, metric *goquery.Selection) {
		label, value := cleanText(metric.Find(".cvss-breakdown__title").Text()), cleanText(metric.Find(".cvss-breakdown__desc").Text())
		switch label {
		case "攻击路径":
			vuln.RiskMetrics.AttackPath = value
		case "攻击复杂度":
			vuln.RiskMetrics.AttackComplexity = value
		case "权限要求":
			vuln.RiskMetrics.PrivilegesRequired = value
		case "影响范围":
			vuln.RiskMetrics.Scope = value
		case "EXP成熟度":
			vuln.RiskMetrics.ExploitMaturity = value
		case "补丁情况":
			vuln.RiskMetrics.PatchStatus = value
		case "数据保密性":
			vuln.RiskMetrics.Confidentiality = value
		case "数据完整性":
			vuln.RiskMetrics.Integrity = value
		case "服务器危害":
			vuln.RiskMetrics.ServerImpact = value
		case "全网数量":
			vuln.RiskMetrics.InternetCount = value
		}
	})
	doc.Find("tr").Each(func(_ int, row *goquery.Selection) {
		cells := row.Find("td")
		if cells.Length() < 2 {
			return
		}
		id := cleanText(cells.Eq(0).Text())
		if aliyunAVDCWEPattern.MatchString(id) {
			vuln.CWEs = append(vuln.CWEs, AVDCWE{ID: strings.ToUpper(id), Name: cleanText(cells.Eq(1).Text())})
		}
	})
	vuln.AffectedSoftware = parseAffectedSoftware(doc)
	vuln.SecurityCoverage = parseSecurityCoverage(doc)
	if vuln.CVE != "" && aliyunAVDCVEPattern.MatchString(vuln.CVE) {
		return nil, errors.New("列表标记无 CVE，但详情页发现 CVE")
	}
	return vuln, nil
}

func parseAffectedSoftware(doc *goquery.Document) []AVDAffectedSoftware {
	result := make([]AVDAffectedSoftware, 0)
	doc.Find("h6").EachWithBreak(func(_ int, heading *goquery.Selection) bool {
		if cleanText(heading.Text()) != "受影响软件情况" {
			return true
		}
		table := heading.NextAll().Find("table").First()
		if table.Length() == 0 {
			table = heading.Parent().NextAll().Find("table").First()
		}
		if table.Length() == 0 {
			table = heading.Parent().Find("table").First()
		}
		table.Find("tr").Each(func(_ int, row *goquery.Selection) {
			cells := row.Find("td.bg-light")
			if cells.Length() < 4 {
				return
			}
			impact := make([]string, 0)
			for i := 4; i < cells.Length(); i++ {
				if value := cleanText(cells.Eq(i).Text()); value != "" {
					impact = append(impact, value)
				}
			}
			result = append(result, AVDAffectedSoftware{Type: cleanText(cells.Eq(0).Text()), Vendor: cleanText(cells.Eq(1).Text()), Product: cleanText(cells.Eq(2).Text()), Version: cleanText(cells.Eq(3).Text()), Impact: strings.Join(impact, " ")})
		})
		return false
	})
	return result
}

func parseSecurityCoverage(doc *goquery.Document) []AVDSecurityCoverage {
	result := make([]AVDSecurityCoverage, 0)
	doc.Find(".card--sidebar").EachWithBreak(func(_ int, card *goquery.Selection) bool {
		if !strings.Contains(cleanText(card.Find(".card__content").First().Text()), "阿里云安全产品覆盖情况") {
			return true
		}
		card.Find("button").Each(func(_ int, button *goquery.Selection) {
			class, _ := button.Attr("class")
			title, _ := button.Attr("title")
			result = append(result, AVDSecurityCoverage{Name: cleanText(button.Text()), Supported: !strings.Contains(class, "disabled"), Description: cleanText(title)})
		})
		return false
	})
	if len(result) > 0 {
		return result
	}
	doc.Find("h6").EachWithBreak(func(_ int, heading *goquery.Selection) bool {
		if cleanText(heading.Text()) != "阿里云安全产品覆盖情况" {
			return true
		}
		container := heading.Parent()
		container.Find("button").Each(func(_ int, button *goquery.Selection) {
			class, _ := button.Attr("class")
			title, _ := button.Attr("title")
			result = append(result, AVDSecurityCoverage{Name: cleanText(button.Text()), Supported: !strings.Contains(class, "disabled"), Description: cleanText(title)})
		})
		return false
	})
	return result
}

func avdSectionText(doc *goquery.Document, heading string) string {
	var result string
	doc.Find("h6").EachWithBreak(func(_ int, item *goquery.Selection) bool {
		if cleanText(item.Text()) == heading {
			result = strings.TrimSpace(item.Next().Text())
			return false
		}
		return true
	})
	return result
}

func resolveAVDURL(raw string) (string, error) {
	base, _ := url.Parse(aliyunAVDBaseURL)
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	resolved := base.ResolveReference(u)
	if err := validateAVDURL(resolved); err != nil {
		return "", err
	}
	return resolved.String(), nil
}

func validateAVDURL(u *url.URL) error {
	if u == nil || u.Scheme != "https" || strings.ToLower(u.Hostname()) != aliyunAVDHost || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return errors.New("阿里云请求 URL 不在固定主机白名单内")
	}
	return nil
}

func cleanText(value string) string {
	value = html.UnescapeString(value)
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
