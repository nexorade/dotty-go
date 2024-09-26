package types

type Response[T any] struct {
	Success bool `json:"success"`
	Data    T    `json:"data"`
}
