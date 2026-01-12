package domain

import "time"

// TokenType represents the purpose of an email token.
type TokenType string

const (
	TokenTypeVerifyEmail    TokenType = "verify-email"
	TokenTypeForgetPassword TokenType = "forget-password"
)

// EmailToken represents a one-time use token for email verification or password reset.
type EmailToken struct {
	ID        string
	UserID    string
	TokenHash string
	Type      TokenType
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// EmailTokenCreate contains data needed to create an email token.
type EmailTokenCreate struct {
	UserID    string
	TokenHash string
	Type      TokenType
	ExpiresAt time.Time
}

// Claims represents JWT claims extracted from a token.
type Claims struct {
	UserID    string
	TokenType string // "access" or "refresh"
}
