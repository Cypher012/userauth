package domain

import "time"

// Session represents a user's login session.
type Session struct {
	ID               string
	UserID           string
	RefreshTokenHash string
	DeviceName       string
	DeviceInfo       string
	IPAddress        string
	ExpiresAt        time.Time
	CreatedAt        time.Time
	LastUsed         time.Time
	RevokedAt        *time.Time
}

// SessionCreate contains data needed to create a new session.
type SessionCreate struct {
	UserID           string
	RefreshTokenHash string
	DeviceName       string
	DeviceInfo       string
	IPAddress        string
	ExpiresAt        time.Time
}
