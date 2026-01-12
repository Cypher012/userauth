package auth

import (
	"time"
)

// Config holds all configuration for the auth module.
// All fields are injectable at initialization time.
type Config struct {
	// JWT settings
	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// Email token settings
	EmailTokenSecret string
	EmailTokenTTL    time.Duration

	// Cookie settings
	CookieName     string
	CookiePath     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite string // "lax", "strict", "none"

	// Base URL for email links
	BaseURL string

	// Route prefix (e.g., "/api/v1/auth")
	RoutePrefix string
}

// DefaultConfig returns a Config with sensible defaults.
// Secrets must still be provided.
func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 1 * time.Hour,
		EmailTokenTTL:   1 * time.Hour,

		CookieName:     "refresh_token",
		CookiePath:     "/",
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieSameSite: "lax",

		RoutePrefix: "/auth",
	}
}

// Validate checks that required configuration is present.
func (c Config) Validate() error {
	if c.JWTSecret == "" {
		return ErrConfigMissingJWTSecret
	}
	if c.EmailTokenSecret == "" {
		return ErrConfigMissingEmailTokenSecret
	}
	if c.BaseURL == "" {
		return ErrConfigMissingBaseURL
	}
	return nil
}
