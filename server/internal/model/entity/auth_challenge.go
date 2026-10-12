package entity

import "time"

type AuthChallenge struct {
	ID              int64      `gorm:"column:id;primaryKey;autoIncrement"`
	ChallengeID     string     `gorm:"column:challenge_id;size:64"`
	ChallengeType   string     `gorm:"column:challenge_type;size:32"`
	TargetAngle     float64    `gorm:"column:target_angle"`
	AnswerTolerance float64    `gorm:"column:answer_tolerance"`
	SceneSeed       int64      `gorm:"column:scene_seed"`
	ClientIP        *string    `gorm:"column:client_ip"`
	ExpiresAt       time.Time  `gorm:"column:expires_at"`
	UsedAt          *time.Time `gorm:"column:used_at"`
	CreatedAt       time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt       time.Time  `gorm:"column:updated_at;autoUpdateTime"`
}

func (AuthChallenge) TableName() string {
	return "manscan_auth_challenges"
}
