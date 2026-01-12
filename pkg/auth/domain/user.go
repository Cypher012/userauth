package domain

import "time"

// User represents a user in the system.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	IsVerified   bool
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserCreate contains data needed to create a new user.
type UserCreate struct {
	Email        string
	PasswordHash string
}
