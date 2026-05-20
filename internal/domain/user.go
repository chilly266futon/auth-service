package domain

import "time"

type User struct {
	ID           string
	Email        string
	Username     string
	PasswordHash string
	Roles        []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
