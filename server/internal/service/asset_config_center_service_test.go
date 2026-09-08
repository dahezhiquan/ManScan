package service

import (
	"context"
	"errors"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
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

func TestAssetConfigCenterServiceSmallCategoryOptionsMapsRepositoryResult(t *testing.T) {
	t.Parallel()

	repo := &assetConfigCenterRepositoryStub{
		smallCategories: []string{"api", "web"},
	}

	svc := NewAssetConfigCenterService(repo)
	result, err := svc.SmallCategoryOptions(context.Background(), dto.ListAssetConfigCenterSmallCategoryOptionsQuery{
		BigCategories: []string{"app"},
	})
	if err != nil {
		t.Fatalf("SmallCategoryOptions() error = %v", err)
	}
	if len(result.Items) != 2 || result.Items[0] != "api" || result.Items[1] != "web" {
		t.Fatalf("result = %+v, want [api web]", result)
	}
}

func TestAssetConfigCenterServiceCreateRejectsDuplicateItemName(t *testing.T) {
	t.Parallel()

	repo := &assetConfigCenterRepositoryStub{
		itemByName: &entity.AssetConfigCenter{ID: 1, ItemName: "Alpha Config"},
	}
	svc := NewAssetConfigCenterService(repo)

	_, err := svc.Create(context.Background(), dto.CreateAssetConfigCenterRequest{
		ItemName:      "Alpha Config",
		BigCategory:   "app",
		SmallCategory: "web",
		Status:        "enabled",
	})
	if !errors.Is(err, ErrDuplicateAssetConfigCenterItemName) {
		t.Fatalf("Create() error = %v, want ErrDuplicateAssetConfigCenterItemName", err)
	}
}

func TestAssetConfigCenterServiceUpdateAllowsCurrentItemName(t *testing.T) {
	t.Parallel()

	repo := &assetConfigCenterRepositoryStub{
		itemByID:   &entity.AssetConfigCenter{ID: 7, ItemName: "Alpha Config"},
		itemByName: &entity.AssetConfigCenter{ID: 7, ItemName: "Alpha Config"},
	}
	svc := NewAssetConfigCenterService(repo)

	item, err := svc.Update(context.Background(), 7, dto.UpdateAssetConfigCenterRequest{
		ItemName:      " Alpha Config ",
		BigCategory:   " app ",
		SmallCategory: " web ",
		Status:        " ENABLED ",
		Description:   " updated ",
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if item.ID != 7 || item.ItemName != "Alpha Config" || item.Status != "enabled" || item.Description != "updated" {
		t.Fatalf("item = %+v, want normalized updated item", item)
	}
	if repo.updated == nil || repo.updated.ID != 7 {
		t.Fatalf("updated entity = %+v, want id 7", repo.updated)
	}
}

func TestAssetConfigCenterServiceDeleteChecksExistence(t *testing.T) {
	t.Parallel()

	repo := &assetConfigCenterRepositoryStub{
		itemByIDErr: gorm.ErrRecordNotFound,
	}
	svc := NewAssetConfigCenterService(repo)

	_, err := svc.Delete(context.Background(), 404)
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("Delete() error = %v, want gorm.ErrRecordNotFound", err)
	}
}

type assetConfigCenterRepositoryStub struct {
	listResult      *dto.PageResult[entity.AssetConfigCenter]
	smallCategories []string
	itemByID        *entity.AssetConfigCenter
	itemByName      *entity.AssetConfigCenter
	created         *entity.AssetConfigCenter
	updated         *entity.AssetConfigCenter

	itemByIDErr   error
	itemByNameErr error
	createErr     error
	updateErr     error
	deleteErr     error
}

func (s *assetConfigCenterRepositoryStub) Create(_ context.Context, item *entity.AssetConfigCenter) error {
	s.created = item
	return s.createErr
}

func (s *assetConfigCenterRepositoryStub) List(_ context.Context, _ dto.ListAssetConfigCentersQuery) (*dto.PageResult[entity.AssetConfigCenter], error) {
	return s.listResult, nil
}

func (s *assetConfigCenterRepositoryStub) ListSmallCategoriesByBigCategories(_ context.Context, _ []string) ([]string, error) {
	return s.smallCategories, nil
}

func (s *assetConfigCenterRepositoryStub) FindByID(_ context.Context, _ int64) (*entity.AssetConfigCenter, error) {
	if s.itemByIDErr != nil {
		return nil, s.itemByIDErr
	}
	if s.itemByID == nil {
		return nil, gorm.ErrRecordNotFound
	}
	return s.itemByID, nil
}

func (s *assetConfigCenterRepositoryStub) FindByItemName(_ context.Context, _ string) (*entity.AssetConfigCenter, error) {
	if s.itemByNameErr != nil {
		return nil, s.itemByNameErr
	}
	if s.itemByName == nil {
		return nil, gorm.ErrRecordNotFound
	}
	return s.itemByName, nil
}

func (s *assetConfigCenterRepositoryStub) Update(_ context.Context, item *entity.AssetConfigCenter) error {
	s.updated = item
	return s.updateErr
}

func (s *assetConfigCenterRepositoryStub) Delete(_ context.Context, _ int64) (int64, error) {
	if s.deleteErr != nil {
		return 0, s.deleteErr
	}
	return 1, nil
}
