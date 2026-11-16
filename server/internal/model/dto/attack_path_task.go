package dto

import "time"

// AttackPathTaskResponse describes progress without exposing submitted paths.
type AttackPathTaskResponse struct {
	ID           string     `json:"id"`
	Status       string     `json:"status"`
	Total        int        `json:"total"`
	Processed    int        `json:"processed"`
	Kept         int        `json:"kept"`
	ErrorMessage string     `json:"error_message,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
}
