package service

import (
	"context"
	"io"
	"strconv"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/repository"
)

var domainExportHeaders = []interface{}{
	"domain", "owner", "title", "first_alive_at", "last_alive_at", "region",
	"risk_level", "has_form", "has_upload", "has_admin", "has_uc_login",
	"has_baidu_login", "screenshot_path", "manual_note", "http_status_code",
	"request", "response", "is_alive", "vulnerability_count", "critical_count",
	"high_count", "medium_count", "low_count", "component_count",
	"service_assets", "title_histories",
}

var domainExportWidths = []float64{
	36, 22, 42, 24, 24, 22, 14, 13, 14, 13, 15, 18, 42, 50,
	17, 70, 80, 13, 20, 16, 14, 17, 14, 19, 80, 80,
}

var hostExportHeaders = []interface{}{
	"ip_address", "region", "owner", "os_type", "os_version", "scan_created_at",
	"last_alive_at", "manual_note", "is_alive", "related_domains", "risk_level",
	"vulnerability_count", "critical_count", "high_count", "medium_count",
	"low_count", "port_count", "ports",
}

var hostExportWidths = []float64{
	25, 22, 22, 18, 22, 24, 24, 50, 13, 50, 14, 20, 16, 14, 17, 14, 14, 90,
}

// Export writes all filtered domain assets and their detail collections to XLSX.
func (s *assetDomainService) Export(ctx context.Context, query dto.ListAssetDomainsQuery, output io.Writer) error {
	return writeExportWorkbook(output, "domain_assets", domainExportHeaders, domainExportWidths, func(visit func([]interface{}) error) error {
		return s.repository.EachFiltered(ctx, query, func(record repository.AssetDomainExportRecord) error {
			values, err := domainExportRow(record)
			if err != nil {
				return err
			}
			return visit(values)
		})
	})
}

// Export writes all filtered host assets and their port details to XLSX.
func (s *assetHostService) Export(ctx context.Context, query dto.ListAssetHostsQuery, output io.Writer) error {
	return writeExportWorkbook(output, "host_assets", hostExportHeaders, hostExportWidths, func(visit func([]interface{}) error) error {
		return s.repository.EachFiltered(ctx, query, func(record repository.AssetHostExportRecord) error {
			values, err := hostExportRow(record)
			if err != nil {
				return err
			}
			return visit(values)
		})
	})
}

func domainExportRow(record repository.AssetDomainExportRecord) ([]interface{}, error) {
	list := toAssetDomainListItem(record.List)
	detail := toAssetDomainDetail(repository.AssetDomainDetailRecord{
		AssetDomain: record.List.AssetDomain, ServiceAssets: record.ServiceAssets, TitleHistories: record.TitleHistories,
	})
	services, err := exportJSON(detail.ServiceAssets)
	if err != nil {
		return nil, err
	}
	histories, err := exportJSON(detail.TitleHistories)
	if err != nil {
		return nil, err
	}
	return []interface{}{
		list.Domain, list.Owner, list.Title, exportOptionalTime(list.FirstAliveAt),
		exportOptionalTime(list.LastAliveAt), list.Region, list.RiskLevel,
		exportOptionalBool(list.HasForm), exportOptionalBool(list.HasUpload),
		exportOptionalBool(list.HasAdmin), exportOptionalBool(list.HasUCLogin),
		exportOptionalBool(list.HasBaiduLogin), list.ScreenshotPath, list.ManualNote,
		exportOptionalUint(list.HTTPStatusCode), list.Request, list.Response,
		strconv.FormatBool(list.IsAlive), list.VulnerabilityCount, list.CriticalCount,
		list.HighCount, list.MediumCount, list.LowCount, list.ComponentCount,
		services, histories,
	}, nil
}

func hostExportRow(record repository.AssetHostExportRecord) ([]interface{}, error) {
	list := toAssetHostListItem(record.List)
	detail := toAssetHostDetail(repository.AssetHostDetailRecord{
		AssetHost: record.List.AssetHost, Ports: record.Ports,
	})
	ports, err := exportJSON(detail.Ports)
	if err != nil {
		return nil, err
	}
	return []interface{}{
		list.IPAddress, list.Region, list.Owner, list.OSType, list.OSVersion,
		exportTime(list.ScanCreatedAt), exportOptionalTime(list.LastAliveAt),
		list.ManualNote, strconv.FormatBool(list.IsAlive), list.RelatedDomains,
		list.RiskLevel, list.VulnerabilityCount, list.CriticalCount, list.HighCount,
		list.MediumCount, list.LowCount, list.PortCount, ports,
	}, nil
}

func exportOptionalBool(value *bool) string {
	if value == nil {
		return ""
	}
	return strconv.FormatBool(*value)
}
