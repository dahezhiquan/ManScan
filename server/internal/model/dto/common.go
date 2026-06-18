package dto

type PageResult[T any] struct {
	Page       int `json:"page"`
	PageSize   int `json:"pageSize"`
	Total      int `json:"total"`
	TotalPages int `json:"totalPages"`
	Items      []T `json:"items"`
}
