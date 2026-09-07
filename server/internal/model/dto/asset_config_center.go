package dto

type ListAssetConfigCentersQuery struct {
	Page            int
	PageSize        int
	ItemNames       []string
	BigCategories   []string
	SmallCategories []string
	Statuses        []string
}

type AssetConfigCenterListItem struct {
	ID            int64  `json:"id"`
	ItemName      string `json:"item_name"`
	BigCategory   string `json:"big_category"`
	SmallCategory string `json:"small_category"`
	Status        string `json:"status"`
	Description   string `json:"description"`
}
