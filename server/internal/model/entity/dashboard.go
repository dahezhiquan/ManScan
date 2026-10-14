package entity

// DashboardVulnerabilityCount 映射按状态和等级聚合的漏洞数量。
type DashboardVulnerabilityCount struct {
	Status   string `gorm:"column:status"`
	Severity string `gorm:"column:severity"`
	Count    int64  `gorm:"column:count"`
}

// DashboardAssetRiskCount 映射资产最高风险等级的数量。
type DashboardAssetRiskCount struct {
	Critical int64 `gorm:"column:critical"`
	High     int64 `gorm:"column:high"`
	Medium   int64 `gorm:"column:medium"`
	Low      int64 `gorm:"column:low"`
	NoRisk   int64 `gorm:"column:no_risk"`
	Unknown  int64 `gorm:"column:unknown"`
}

// DashboardHostCount 映射主机排行榜的数量。
type DashboardHostCount struct {
	IPAddress string `gorm:"column:ip_address"`
	Count     int64  `gorm:"column:count"`
}

// DashboardFingerprintCount 映射服务指纹排行榜的数量。
type DashboardFingerprintCount struct {
	Fingerprint string `gorm:"column:fingerprint"`
	Count       int64  `gorm:"column:count"`
}
