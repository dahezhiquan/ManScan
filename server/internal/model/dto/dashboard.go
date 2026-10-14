package dto

// DashboardVulnerabilityStatusCounts 表示各处理状态的漏洞数量。
type DashboardVulnerabilityStatusCounts struct {
	Total         int64 `json:"total"`
	Unreviewed    int64 `json:"unreviewed"`
	Confirmed     int64 `json:"confirmed"`
	Ticketed      int64 `json:"ticketed"`
	Fixed         int64 `json:"fixed"`
	FalsePositive int64 `json:"false_positive"`
	Ignored       int64 `json:"ignored"`
}

// DashboardPendingVulnerabilityCounts 表示未审核漏洞的等级分布。
type DashboardPendingVulnerabilityCounts struct {
	Total    int64 `json:"total"`
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
}

// DashboardOverviewResponse 表示主页概览统计。
type DashboardOverviewResponse struct {
	VulnerabilityStatus    DashboardVulnerabilityStatusCounts  `json:"vulnerability_status"`
	PendingVulnerabilities DashboardPendingVulnerabilityCounts `json:"pending_vulnerabilities"`
	HighRiskOpenPorts      int64                               `json:"high_risk_open_ports"`
}

// DashboardAssetRiskCounts 表示资产最高风险等级的数量分布。
type DashboardAssetRiskCounts struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	NoRisk   int64 `json:"no_risk"`
	Unknown  int64 `json:"unknown"`
}

// DashboardAssetRisksResponse 表示主机及域名资产风险统计。
type DashboardAssetRisksResponse struct {
	Hosts   DashboardAssetRiskCounts `json:"hosts"`
	Domains DashboardAssetRiskCounts `json:"domains"`
}

// DashboardHostVulnerabilityRank 表示主机漏洞数量排名。
type DashboardHostVulnerabilityRank struct {
	IPAddress          string `json:"ip_address"`
	VulnerabilityCount int64  `json:"vulnerability_count"`
}

// DashboardHostPortRank 表示主机开放端口数量排名。
type DashboardHostPortRank struct {
	IPAddress string `json:"ip_address"`
	PortCount int64  `json:"port_count"`
}

// DashboardHostRankingsResponse 表示两组主机 Top10 排行榜。
type DashboardHostRankingsResponse struct {
	TopVulnerabilities []DashboardHostVulnerabilityRank `json:"top_vulnerabilities"`
	TopPorts           []DashboardHostPortRank          `json:"top_ports"`
}

// DashboardDomainFingerprintRank 表示域名服务指纹数量排名。
type DashboardDomainFingerprintRank struct {
	AppName string `json:"app_name"`
	Count   int64  `json:"count"`
}

// DashboardHostFingerprintRank 表示主机服务指纹数量排名。
type DashboardHostFingerprintRank struct {
	ServiceName string `json:"service_name"`
	Count       int64  `json:"count"`
}

// DashboardServiceFingerprintsResponse 表示两组服务指纹 Top10 排行榜。
type DashboardServiceFingerprintsResponse struct {
	Domains []DashboardDomainFingerprintRank `json:"domains"`
	Hosts   []DashboardHostFingerprintRank   `json:"hosts"`
}
