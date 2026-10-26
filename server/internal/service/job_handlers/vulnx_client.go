package job_handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
)

const defaultVulnxAPIBaseURL = "https://api.projectdiscovery.io"

var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]+$`)

type vulnxAPIResponse struct {
	Data vulnxVulnerability `json:"data"`
}

type vulnxVulnerability struct {
	AgeInDays           *int                   `json:"age_in_days"`
	AffectedProducts    []vulnxAffectedProduct `json:"affected_products"`
	Category            *string                `json:"category"`
	Citations           []vulnxCitation        `json:"citations"`
	CVEID               string                 `json:"cve_id"`
	CreatedAt           *time.Time             `json:"created_at"`
	UpdatedAt           *time.Time             `json:"updated_at"`
	CVECreatedAt        *time.Time             `json:"cve_created_at"`
	CVEUpdatedAt        *time.Time             `json:"cve_updated_at"`
	CVSSMetrics         *string                `json:"cvss_metrics"`
	CVSSScore           *float64               `json:"cvss_score"`
	CWE                 []string               `json:"cwe"`
	Description         *string                `json:"description"`
	DocID               string                 `json:"doc_id"`
	DocType             string                 `json:"doc_type"`
	EPSSPercentile      *float64               `json:"epss_percentile"`
	EPSSScore           *float64               `json:"epss_score"`
	Exposure            vulnxExposure          `json:"exposure"`
	Filename            *string                `json:"filename"`
	H1                  *vulnxH1               `json:"h1"`
	Impact              *string                `json:"impact"`
	IsAuth              *bool                  `json:"is_auth"`
	IsKEV               *bool                  `json:"is_kev"`
	IsOSS               *bool                  `json:"is_oss"`
	IsPatchAvailable    *bool                  `json:"is_patch_available"`
	IsTemplate          *bool                  `json:"is_template"`
	IsPOC               *bool                  `json:"is_poc"`
	IsRemote            *bool                  `json:"is_remote"`
	IsVKEV              *bool                  `json:"is_vkev"`
	Name                *string                `json:"name"`
	NTPS                *float64               `json:"ntps"`
	POCCount            *uint                  `json:"poc_count"`
	POCFirstSeen        *time.Time             `json:"poc_first_seen"`
	POCs                []vulnxPOC             `json:"pocs"`
	Product             *string                `json:"product"`
	Remediation         *string                `json:"remediation"`
	Severity            *string                `json:"severity"`
	VulnStatus          *string                `json:"vuln_status"`
	VulnerabilityType   *string                `json:"vulnerability_type"`
	VulnerabilityImpact []string               `json:"vulnerability_impact"`
	Vendor              *string                `json:"vendor"`
}

type vulnxAffectedProduct struct {
	CPE             []string `json:"cpe"`
	Category        *string  `json:"category"`
	DeploymentModel *string  `json:"deployment_model"`
	Industry        *string  `json:"industry"`
	Product         string   `json:"product"`
	Summary         *string  `json:"summary"`
	Vendor          *string  `json:"vendor"`
}

type vulnxCitation struct {
	AddedAt *time.Time `json:"added_at"`
	Source  *string    `json:"source"`
	URL     string     `json:"url"`
}

type vulnxPOC struct {
	AddedAt *time.Time `json:"added_at"`
	Source  *string    `json:"source"`
	URL     string     `json:"url"`
}

type vulnxH1 struct {
	Rank    uint `json:"rank"`
	Reports uint `json:"reports"`
}

type vulnxExposure struct {
	MaxHosts *uint64             `json:"max_hosts"`
	MinHosts *uint64             `json:"min_hosts"`
	Values   []vulnxExposureItem `json:"values"`
}

type vulnxExposureItem struct {
	ID       string       `json:"id"`
	MaxHosts *uint64      `json:"max_hosts"`
	MinHosts *uint64      `json:"min_hosts"`
	Shodan   *vulnxShodan `json:"shodan"`
}

type vulnxShodan struct {
	MaxHosts *uint64  `json:"max_hosts"`
	MinHosts *uint64  `json:"min_hosts"`
	Queries  []string `json:"queries"`
}

// VulnxClient 查询 ProjectDiscovery VulnX 漏洞详情。
type VulnxClient struct {
	HTTPClient    *http.Client
	BaseURL       string
	APIKey        string
	BeforeRequest func(context.Context) error
}

// NewVulnxClient 创建 VulnX 客户端。
func NewVulnxClient(apiKey string) *VulnxClient {
	return &VulnxClient{
		HTTPClient: &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		BaseURL:    defaultVulnxAPIBaseURL,
		APIKey:     strings.TrimSpace(apiKey),
	}
}

// Fetch 获取一个 CVE 的完整情报快照并转换为数据库实体。
func (c *VulnxClient) Fetch(ctx context.Context, cveID string) (*repository.VulnerabilityIntelligenceBundle, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !cveIDPattern.MatchString(cveID) {
		return nil, errors.New("CVE 编号格式不合法")
	}
	base := strings.TrimRight(c.BaseURL, "/")
	endpoint := base + "/v2/vulnerability/" + url.PathEscape(cveID)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "manscan-vulnx-sync")
	if c.APIKey != "" {
		request.Header.Set("X-Api-Key", c.APIKey)
	}
	if c.BeforeRequest != nil {
		if err := c.BeforeRequest(ctx); err != nil {
			return nil, err
		}
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("VulnX API 返回 HTTP %d", response.StatusCode)
	}
	var payload vulnxAPIResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("解析 VulnX 响应失败: %w", err)
	}
	if payload.Data.CVEID == "" && payload.Data.DocID == "" {
		return nil, errors.New("VulnX 响应缺少漏洞编号")
	}
	bundle, err := payload.Data.bundle(cveID)
	if err != nil {
		return nil, err
	}
	if bundle.Record.VulnerabilityID != cveID {
		return nil, errors.New("VulnX 响应漏洞编号与请求不一致")
	}
	return bundle, nil
}

func (v vulnxVulnerability) bundle(requestedID string) (*repository.VulnerabilityIntelligenceBundle, error) {
	id := strings.ToUpper(strings.TrimSpace(v.CVEID))
	if id == "" {
		id = strings.ToUpper(strings.TrimSpace(v.DocID))
	}
	if id == "" {
		id = requestedID
	}
	category := v.Category
	if category == nil || strings.TrimSpace(*category) == "" {
		fallback := strings.TrimSuffix(strings.TrimSpace(v.DocType), "_template")
		if fallback != "" {
			category = &fallback
		}
	}
	record := &entity.VulnerabilityIntelligenceRecord{
		Source: "vulnx", VulnerabilityID: id, AgeInDays: v.AgeInDays, Category: category,
		CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt, CVSSMetrics: v.CVSSMetrics, CVSSScore: v.CVSSScore,
		CWE: v.CWE, Description: v.Description, EPSSPercentile: v.EPSSPercentile, EPSSScore: v.EPSSScore,
		MaxHosts: v.Exposure.MaxHosts, MinHosts: v.Exposure.MinHosts, Filename: v.Filename, Impact: v.Impact,
		VulName: v.Name, IsAuth: v.IsAuth, IsKEV: v.IsKEV, IsOSS: v.IsOSS, IsPatchAvailable: v.IsPatchAvailable,
		IsTemplate: v.IsTemplate, IsPOC: v.IsPOC, IsRemote: v.IsRemote, IsVKEV: v.IsVKEV, NTPS: v.NTPS,
		POCCount: v.POCCount, POCFirstSeen: v.POCFirstSeen, Product: v.Product, Vendor: v.Vendor,
		Remediation: v.Remediation, Severity: v.Severity, VulnStatus: v.VulnStatus,
		VulnerabilityType: v.VulnerabilityType, VulnerabilityImpact: v.VulnerabilityImpact,
	}
	if v.H1 != nil {
		record.H1Rank = &v.H1.Rank
		record.H1Reports = &v.H1.Reports
	}
	if record.CreatedAt == nil || record.CreatedAt.IsZero() {
		record.CreatedAt = v.CVECreatedAt
	}
	if record.UpdatedAt == nil || record.UpdatedAt.IsZero() {
		record.UpdatedAt = v.CVEUpdatedAt
	}
	bundle := &repository.VulnerabilityIntelligenceBundle{Record: record}
	for _, item := range v.Citations {
		if item.URL == "" {
			continue
		}
		bundle.Articles = append(bundle.Articles, entity.VulnerabilityIntelligenceArticle{VulnerabilityID: id, AddedAt: item.AddedAt, Source: item.Source, URL: item.URL})
	}
	for _, item := range v.AffectedProducts {
		if item.Product == "" {
			continue
		}
		bundle.Components = append(bundle.Components, entity.VulnerabilityIntelligenceComponent{VulnerabilityID: id, CPE: item.CPE, Category: item.Category, DeploymentModel: item.DeploymentModel, Industry: item.Industry, Product: item.Product, Summary: item.Summary, Vendor: item.Vendor})
	}
	for _, item := range v.POCs {
		if item.URL == "" {
			continue
		}
		bundle.POCs = append(bundle.POCs, entity.VulnerabilityIntelligencePOC{VulnerabilityID: id, AddedAt: item.AddedAt, Source: item.Source, URL: item.URL})
	}
	for _, item := range v.Exposure.Values {
		if item.ID == "" || item.Shodan == nil {
			continue
		}
		maxHosts, minHosts := item.Shodan.MaxHosts, item.Shodan.MinHosts
		if maxHosts == nil && minHosts == nil {
			maxHosts, minHosts = item.MaxHosts, item.MinHosts
		}
		productName := item.ID
		bundle.ShodanItems = append(bundle.ShodanItems, entity.VulnerabilityIntelligenceShodanExposure{VulnerabilityID: id, ProductName: &productName, MaxHosts: maxHosts, MinHosts: minHosts, SearchQueries: item.Shodan.Queries})
	}
	return bundle, nil
}
