package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

func TestAssetConfigCenterHandlerListParsesFilters(t *testing.T) {
	t.Parallel()

	svc := &assetConfigCenterServiceStub{
		listFunc: func(_ dto.ListAssetConfigCentersQuery) (*dto.PageResult[dto.AssetConfigCenterListItem], error) {
			return &dto.PageResult[dto.AssetConfigCenterListItem]{
				Page:       2,
				PageSize:   5,
				Total:      1,
				TotalPages: 1,
				Items: []dto.AssetConfigCenterListItem{
					{ID: 1, ItemName: "Alpha Config", BigCategory: "app", SmallCategory: "web", Status: "enabled"},
				},
			}, nil
		},
	}

	h := NewAssetConfigCenterHandler(svc)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/asset-config-centers", h.List)

	req := httptest.NewRequest(http.MethodGet, "/asset-config-centers?page=2&page_size=5&item_name=alpha,beta&big_category=app&small_category=web&status=enabled", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if svc.lastQuery == nil {
		t.Fatalf("service was not called")
	}
	if svc.lastQuery.Page != 2 || svc.lastQuery.PageSize != 5 {
		t.Fatalf("query page/page_size = %+v, want 2/5", svc.lastQuery)
	}
	if len(svc.lastQuery.ItemNames) != 2 || svc.lastQuery.ItemNames[0] != "alpha" || svc.lastQuery.ItemNames[1] != "beta" {
		t.Fatalf("item names = %+v, want [alpha beta]", svc.lastQuery.ItemNames)
	}
	if len(svc.lastQuery.BigCategories) != 1 || svc.lastQuery.BigCategories[0] != "app" {
		t.Fatalf("big categories = %+v, want [app]", svc.lastQuery.BigCategories)
	}
	if len(svc.lastQuery.SmallCategories) != 1 || svc.lastQuery.SmallCategories[0] != "web" {
		t.Fatalf("small categories = %+v, want [web]", svc.lastQuery.SmallCategories)
	}
	if len(svc.lastQuery.Statuses) != 1 || svc.lastQuery.Statuses[0] != "enabled" {
		t.Fatalf("statuses = %+v, want [enabled]", svc.lastQuery.Statuses)
	}
}

func TestAssetConfigCenterHandlerCreateReturnsInvalidParamsForDuplicateItemName(t *testing.T) {
	t.Parallel()

	svc := &assetConfigCenterServiceStub{
		createErr: service.ErrDuplicateAssetConfigCenterItemName,
	}
	h := NewAssetConfigCenterHandler(svc)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/asset-config-centers", h.Create)

	body := bytes.NewBufferString(`{"item_name":"Alpha","big_category":"app","small_category":"web","status":"enabled"}`)
	req := httptest.NewRequest(http.MethodPost, "/asset-config-centers", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestAssetConfigCenterHandlerSmallCategoryOptionsParsesBigCategories(t *testing.T) {
	t.Parallel()

	svc := &assetConfigCenterServiceStub{
		smallCategoryOptionsFunc: func(query dto.ListAssetConfigCenterSmallCategoryOptionsQuery) (*dto.AssetConfigCenterOptions, error) {
			if len(query.BigCategories) != 2 || query.BigCategories[0] != "app" || query.BigCategories[1] != "security" {
				t.Fatalf("big categories = %+v, want [app security]", query.BigCategories)
			}
			return &dto.AssetConfigCenterOptions{Items: []string{"api", "web"}}, nil
		},
	}

	h := NewAssetConfigCenterHandler(svc)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/asset-config-centers/options/small-categories", h.SmallCategoryOptions)

	req := httptest.NewRequest(http.MethodGet, "/asset-config-centers/options/small-categories?big_category=app&big_category=security", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
}

type assetConfigCenterServiceStub struct {
	lastQuery                *dto.ListAssetConfigCentersQuery
	lastSmallCategoryQuery   *dto.ListAssetConfigCenterSmallCategoryOptionsQuery
	listFunc                 func(dto.ListAssetConfigCentersQuery) (*dto.PageResult[dto.AssetConfigCenterListItem], error)
	smallCategoryOptionsFunc func(dto.ListAssetConfigCenterSmallCategoryOptionsQuery) (*dto.AssetConfigCenterOptions, error)
	createErr                error
	updateErr                error
	deleteErr                error
}

func (s *assetConfigCenterServiceStub) Create(_ context.Context, _ dto.CreateAssetConfigCenterRequest) (*dto.AssetConfigCenterListItem, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	return &dto.AssetConfigCenterListItem{ID: 1, ItemName: "Alpha", BigCategory: "app", SmallCategory: "web", Status: "enabled"}, nil
}

func (s *assetConfigCenterServiceStub) List(_ context.Context, query dto.ListAssetConfigCentersQuery) (*dto.PageResult[dto.AssetConfigCenterListItem], error) {
	copyQuery := query
	s.lastQuery = &copyQuery
	return s.listFunc(query)
}

func (s *assetConfigCenterServiceStub) SmallCategoryOptions(_ context.Context, query dto.ListAssetConfigCenterSmallCategoryOptionsQuery) (*dto.AssetConfigCenterOptions, error) {
	copyQuery := query
	s.lastSmallCategoryQuery = &copyQuery
	if s.smallCategoryOptionsFunc != nil {
		return s.smallCategoryOptionsFunc(query)
	}
	return &dto.AssetConfigCenterOptions{Items: []string{"web"}}, nil
}

func (s *assetConfigCenterServiceStub) Update(_ context.Context, _ int64, _ dto.UpdateAssetConfigCenterRequest) (*dto.AssetConfigCenterListItem, error) {
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	return &dto.AssetConfigCenterListItem{ID: 1, ItemName: "Alpha", BigCategory: "app", SmallCategory: "web", Status: "enabled"}, nil
}

func (s *assetConfigCenterServiceStub) Delete(_ context.Context, itemID int64) (*dto.DeleteAssetConfigCenterResponse, error) {
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	return &dto.DeleteAssetConfigCenterResponse{ID: itemID, DeletedCount: 1}, nil
}
