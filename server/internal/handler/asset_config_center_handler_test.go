package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"ManScan/server/internal/model/dto"

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

type assetConfigCenterServiceStub struct {
	lastQuery *dto.ListAssetConfigCentersQuery
	listFunc  func(dto.ListAssetConfigCentersQuery) (*dto.PageResult[dto.AssetConfigCenterListItem], error)
}

func (s *assetConfigCenterServiceStub) List(_ context.Context, query dto.ListAssetConfigCentersQuery) (*dto.PageResult[dto.AssetConfigCenterListItem], error) {
	copyQuery := query
	s.lastQuery = &copyQuery
	return s.listFunc(query)
}
