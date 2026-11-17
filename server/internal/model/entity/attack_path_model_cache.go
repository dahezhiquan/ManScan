package entity

import "time"

// AttackPathModelCache stores a validated model decision without the raw path.
type AttackPathModelCache struct {
	Key       string    `gorm:"column:key;primaryKey;size:64"`
	Malicious bool      `gorm:"column:malicious;not null;check:malicious IN (0,1)"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"`
}

// TableName versions the on-disk format independently of the classification policy.
func (AttackPathModelCache) TableName() string { return "attack_path_model_cache_v1" }
