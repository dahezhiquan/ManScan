package dto

type ListTemplatesQuery struct {
	Page       int
	Names      []string
	Tags       []string
	Severities []string
	Protocols  []string
	IsKEV      *bool
	IsCVE      *bool
}

type TemplateListItem struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Author      string   `json:"author"`
	Protocols   []string `json:"protocols,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type TemplateDetail struct {
	ID          string   `json:"id"`
	Protocols   []string `json:"protocols"`
	Name        string   `json:"name"`
	Tags        []string `json:"tags"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Impact      string   `json:"impact"`
	Remediation string   `json:"remediation"`
	Reference   []string `json:"reference"`
	CVSSScore   float64  `json:"cvssScore"`
	Vendor      string   `json:"vendor"`
	Product     string   `json:"product"`
	ShodanQuery []string `json:"shodanQuery"`
	FofaQuery   []string `json:"fofaQuery"`
	Content     string   `json:"content"`
}

type TemplateOptions struct {
	Items []string `json:"items"`
}

type TemplateStats struct {
	TemplateCount            int `json:"templateCount"`
	KEVTemplateCount         int `json:"kevTemplateCount"`
	CVETemplateCount         int `json:"cveTemplateCount"`
	FingerprintTemplateCount int `json:"fingerprintTemplateCount"`
}
