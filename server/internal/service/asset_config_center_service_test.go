package service

import (
	"context"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
)

func TestAssetConfigCenterServiceListMapsRepositoryResult(t *testing.T) {
	t.Parallel()

	repo := &assetConfigCenterRepositoryStub{
		listResult: &dto.PageResult[entity.AssetConfigCenter]{
			Page:       1,
			PageSize:   10,
			Total:      1,
			TotalPages: 1,
			Items: []entity.AssetConfigCenter{
				{ID: 7, ItemName: "Alpha Config", BigCategory: "app", SmallCategory: "web", Status: "enabled"},
			},
		},
	}

	svc := NewAssetConfigCenterService(repo)
	result, err := svc.List(context.Background(), dto.ListAssetConfigCentersQuery{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if result.Total != 1 || len(result.Items) != 1 {
		t.Fatalf("result = %+v, want one item", result)
	}
	if result.Items[0].ItemName != "Alpha Config" || result.Items[0].Status != "enabled" {
		t.Fatalf("mapped item = %+v, want Alpha Config/enabled", result.Items[0])
	}
}

type assetConfigCenterRepositoryStub struct {
	listResult *dto.PageResult[entity.AssetConfigCenter]
}

func (s *assetConfigCenterRepositoryStub) List(_ context.Context, _ dto.ListAssetConfigCentersQuery) (*dto.PageResult[entity.AssetConfigCenter], error) {
	return s.listResult, nil
}
