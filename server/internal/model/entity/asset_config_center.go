package entity

type AssetConfigCenter struct {
	ID            int64   `gorm:"column:id;primaryKey;autoIncrement"`
	ItemName      string  `gorm:"column:item_name"`
	BigCategory   string  `gorm:"column:big_category"`
	SmallCategory string  `gorm:"column:small_category"`
	Status        string  `gorm:"column:status"`
	Description   *string `gorm:"column:description"`
}

func (AssetConfigCenter) TableName() string {
	return "manscan_asset_config_centers"
}
