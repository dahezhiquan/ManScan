package dto

import "time"

type LoginRequest struct {
	Username        string                `json:"username" binding:"required"`
	Password        string                `json:"password" binding:"required"`
	ChallengeID     string                `json:"challenge_id" binding:"required"`
	ChallengeAnswer *LoginChallengeAnswer `json:"challenge_answer" binding:"required"`
}

type LoginChallengeAnswer struct {
	Angle          float64               `json:"angle"`
	DragDurationMS int                   `json:"drag_duration_ms"`
	Track          []ChallengeTrackPoint `json:"track"`
}

type ChallengeTrackPoint struct {
	X int `json:"x"`
	Y int `json:"y"`
	T int `json:"t"`
}

type AuthChallengeResponse struct {
	ChallengeID   string             `json:"challenge_id"`
	ChallengeType string             `json:"challenge_type"`
	ExpiresAt     time.Time          `json:"expires_at"`
	Scene         OrbitalSliderScene `json:"scene"`
	Requirements  ChallengeRules     `json:"requirements"`
}

type OrbitalSliderScene struct {
	Theme       string    `json:"theme"`
	Seed        int64     `json:"seed"`
	CanvasSize  int       `json:"canvas_size"`
	CenterX     int       `json:"center_x"`
	CenterY     int       `json:"center_y"`
	Radius      int       `json:"radius"`
	StartAngle  float64   `json:"start_angle"`
	TargetAngle float64   `json:"target_angle"`
	DecoyAngles []float64 `json:"decoy_angles"`
}

type ChallengeRules struct {
	AngleTolerance    float64 `json:"angle_tolerance"`
	MinDragDurationMS int     `json:"min_drag_duration_ms"`
	MaxDragDurationMS int     `json:"max_drag_duration_ms"`
	MinTrackPoints    int     `json:"min_track_points"`
	MaxTrackPoints    int     `json:"max_track_points"`
}

type LoginResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
	User        UserInfo  `json:"user"`
}

type UserInfo struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type ListUsersQuery struct {
	Page     int
	PageSize int
}

type UserListItem struct {
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

type UpdateUserRequest struct {
	Password *string `json:"password"`
	Role     *string `json:"role"`
	Status   *string `json:"status"`
}

type DeleteUserResponse struct {
	Username     string `json:"username"`
	DeletedCount int64  `json:"deleted_count"`
}

type LogoutResponse struct {
	Revoked bool `json:"revoked"`
}

type LoginFailureResponse struct {
	RemainingAttempts int  `json:"remaining_attempts"`
	Locked            bool `json:"locked"`
}

type ChallengeFailureResponse struct {
	RefreshRequired bool `json:"refresh_required"`
}
