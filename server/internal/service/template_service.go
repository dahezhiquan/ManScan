package service

import (
	"context"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/templateprotocol"
	"ManScan/server/internal/repository"
)

type TemplateService interface {
	List(ctx context.Context, query dto.ListTemplatesQuery) (*dto.PageResult[dto.TemplateListItem], error)
	Detail(ctx context.Context, templateID string) (*dto.TemplateDetail, error)
	Tags(ctx context.Context) (*dto.TemplateOptions, error)
	Protocols(ctx context.Context) (*dto.TemplateOptions, error)
	Stats(ctx context.Context) (*dto.TemplateStats, error)
}

type templateService struct {
	repository repository.TemplateRepository
}

func NewTemplateService(repo repository.TemplateRepository) TemplateService {
	return &templateService{repository: repo}
}

func (s *templateService) List(_ context.Context, query dto.ListTemplatesQuery) (*dto.PageResult[dto.TemplateListItem], error) {
	items, err := s.repository.List()
	if err != nil {
		return nil, err
	}

	filtered := filterTemplateListItems(items, query)
	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := 20
	total := len(filtered)
	totalPages := 0
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	pagedItems := make([]dto.TemplateListItem, 0)
	if start < total {
		pagedItems = append(pagedItems, filtered[start:end]...)
	}

	return &dto.PageResult[dto.TemplateListItem]{
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		Items:      pagedItems,
	}, nil
}

func (s *templateService) Detail(_ context.Context, templateID string) (*dto.TemplateDetail, error) {
	return s.repository.FindByID(templateID)
}

func (s *templateService) Tags(_ context.Context) (*dto.TemplateOptions, error) {
	items, err := s.repository.Tags()
	if err != nil {
		return nil, err
	}
	return &dto.TemplateOptions{Items: items}, nil
}

func (s *templateService) Protocols(_ context.Context) (*dto.TemplateOptions, error) {
	items, err := s.repository.Protocols()
	if err != nil {
		return nil, err
	}
	return &dto.TemplateOptions{Items: items}, nil
}

func (s *templateService) Stats(_ context.Context) (*dto.TemplateStats, error) {
	return s.repository.Stats()
}

func filterTemplateListItems(items []dto.TemplateListItem, query dto.ListTemplatesQuery) []dto.TemplateListItem {
	filtered := items

	if len(query.Names) > 0 {
		keywords := normalizeQueries(query.Names)
		tmp := make([]dto.TemplateListItem, 0, len(filtered))
		for _, item := range filtered {
			name := strings.ToLower(item.Name)
			id := strings.ToLower(strings.TrimSpace(item.ID))
			for _, keyword := range keywords {
				if strings.Contains(name, keyword) || strings.Contains(id, keyword) {
					tmp = append(tmp, item)
					break
				}
			}
		}
		filtered = tmp
	}

	if len(query.Tags) > 0 {
		targets := normalizeQueries(query.Tags)
		tmp := make([]dto.TemplateListItem, 0, len(filtered))
		for _, item := range filtered {
			for _, tag := range item.Tags {
				if contains(targets, strings.ToLower(strings.TrimSpace(tag))) {
					tmp = append(tmp, item)
					break
				}
			}
		}
		filtered = tmp
	}

	if len(query.Severities) > 0 {
		targets := normalizeQueries(query.Severities)
		tmp := make([]dto.TemplateListItem, 0, len(filtered))
		for _, item := range filtered {
			if contains(targets, strings.ToLower(strings.TrimSpace(item.Severity))) {
				tmp = append(tmp, item)
			}
		}
		filtered = tmp
	}

	if len(query.Protocols) > 0 {
		targets := templateprotocol.NormalizeList(query.Protocols)
		tmp := make([]dto.TemplateListItem, 0, len(filtered))
		for _, item := range filtered {
			for _, protocol := range item.Protocols {
				if contains(targets, templateprotocol.Normalize(protocol)) {
					tmp = append(tmp, item)
					break
				}
			}
		}
		filtered = tmp
	}

	if query.IsKEV != nil {
		filtered = filterByTagPresence(filtered, "kev", *query.IsKEV)
	}
	if query.IsCVE != nil {
		filtered = filterByTagPresence(filtered, "cve", *query.IsCVE)
	}

	return filtered
}

func filterByTagPresence(items []dto.TemplateListItem, targetTag string, expected bool) []dto.TemplateListItem {
	targetTag = strings.ToLower(strings.TrimSpace(targetTag))
	filtered := make([]dto.TemplateListItem, 0, len(items))
	for _, item := range items {
		hasTag := false
		for _, tag := range item.Tags {
			if strings.EqualFold(strings.TrimSpace(tag), targetTag) {
				hasTag = true
				break
			}
		}
		if hasTag == expected {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func normalizeQueries(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
