package dto

type ListAssetConfigCentersQuery struct {
	Page            int
	PageSize        int
	ItemNames       []string
	BigCategories   []string
	SmallCategories []string
	Statuses        []string
}

type ListAssetConfigCenterSmallCategoryOptionsQuery struct {
	BigCategories []string
}

type AssetConfigCenterListItem struct {
	ID            int64  `json:"id"`
	ItemName      string `json:"item_name"`
	BigCategory   string `json:"big_category"`
	SmallCategory string `json:"small_category"`
	Status        string `json:"status"`
	Description   string `json:"description"`
}

type CreateAssetConfigCenterRequest struct {
	ItemName      string `json:"item_name" binding:"required"`
	BigCategory   string `json:"big_category" binding:"required"`
	SmallCategory string `json:"small_category" binding:"required"`
	Status        string `json:"status" binding:"required"`
	Description   string `json:"description"`
}

type UpdateAssetConfigCenterRequest struct {
	ItemName      string `json:"item_name" binding:"required"`
	BigCategory   string `json:"big_category" binding:"required"`
	SmallCategory string `json:"small_category" binding:"required"`
	Status        string `json:"status" binding:"required"`
	Description   string `json:"description"`
}

type DeleteAssetConfigCenterResponse struct {
	ID           int64 `json:"id"`
	DeletedCount int64 `json:"deleted_count"`
}

type AssetConfigCenterOptions struct {
	Items []string `json:"items"`
}
