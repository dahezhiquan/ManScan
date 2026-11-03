package repository

import (
	"context"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
)

const assetExportBatchSize = 200

// EachFiltered visits every matching domain asset in list order, including its detail collections.
func (r *assetDomainRepository) EachFiltered(ctx context.Context, query dto.ListAssetDomainsQuery, visit func(AssetDomainExportRecord) error) error {
	rows, err := r.assetDomainListItemsQuery(ctx, query).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	batch := make([]AssetDomainListRecord, 0, assetExportBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		domains := make([]string, 0, len(batch))
		for _, item := range batch {
			domains = append(domains, item.Domain)
		}
		var services []entity.AssetDomainServiceAsset
		if err := r.db.WithContext(ctx).Where("domain IN ?", domains).
			Order("is_alive DESC").Order("last_found_at DESC").Order("id DESC").
			Find(&services).Error; err != nil {
			return err
		}
		var histories []entity.AssetDomainTitleHistory
		if err := r.db.WithContext(ctx).Where("domain IN ?", domains).
			Order("is_alive DESC").Order("latest_title_alive_at DESC").Order("id DESC").
			Find(&histories).Error; err != nil {
			return err
		}
		servicesByDomain := make(map[string][]entity.AssetDomainServiceAsset, len(batch))
		for _, item := range services {
			servicesByDomain[item.Domain] = append(servicesByDomain[item.Domain], item)
		}
		historiesByDomain := make(map[string][]entity.AssetDomainTitleHistory, len(batch))
		for _, item := range histories {
			historiesByDomain[item.Domain] = append(historiesByDomain[item.Domain], item)
		}
		for _, item := range batch {
			if err := visit(AssetDomainExportRecord{
				List: item, ServiceAssets: servicesByDomain[item.Domain], TitleHistories: historiesByDomain[item.Domain],
			}); err != nil {
				return err
			}
		}
		batch = batch[:0]
		return nil
	}
	for rows.Next() {
		var item AssetDomainListRecord
		if err := r.db.ScanRows(rows, &item); err != nil {
			return err
		}
		batch = append(batch, item)
		if len(batch) == assetExportBatchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return flush()
}

// EachFiltered visits every matching host asset in list order, including its ports.
func (r *assetHostRepository) EachFiltered(ctx context.Context, query dto.ListAssetHostsQuery, visit func(AssetHostExportRecord) error) error {
	rows, err := r.assetHostListItemsQuery(ctx, query).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	batch := make([]AssetHostListRecord, 0, assetExportBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		addresses := make([]string, 0, len(batch))
		for _, item := range batch {
			addresses = append(addresses, item.IPAddress)
		}
		var ports []entity.AssetHostPort
		if err := r.db.WithContext(ctx).Where("ip_address IN ?", addresses).
			Order("is_alive DESC").Order("port_number ASC").Order("id ASC").
			Find(&ports).Error; err != nil {
			return err
		}
		portsByHost := make(map[string][]entity.AssetHostPort, len(batch))
		for _, item := range ports {
			portsByHost[item.IPAddress] = append(portsByHost[item.IPAddress], item)
		}
		for _, item := range batch {
			if err := visit(AssetHostExportRecord{List: item, Ports: portsByHost[item.IPAddress]}); err != nil {
				return err
			}
		}
		batch = batch[:0]
		return nil
	}
	for rows.Next() {
		var item AssetHostListRecord
		if err := r.db.ScanRows(rows, &item); err != nil {
			return err
		}
		batch = append(batch, item)
		if len(batch) == assetExportBatchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return flush()
}
