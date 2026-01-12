package cookie

import (
	"errors"
	"net/http"
)

// Manager implements ports.CookieManager.
type Manager struct {
	name     string
	path     string
	secure   bool
	httpOnly bool
	sameSite http.SameSite
	maxAge   int // seconds
}

// Config holds cookie configuration.
type Config struct {
	Name     string
	Path     string
	Secure   bool
	HTTPOnly bool
	SameSite string // "lax", "strict", "none"
	MaxAge   int    // seconds
}

// New creates a new cookie Manager.
func New(cfg Config) *Manager {
	sameSite := http.SameSiteLaxMode
	switch cfg.SameSite {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}

	return &Manager{
		name:     cfg.Name,
		path:     cfg.Path,
		secure:   cfg.Secure,
		httpOnly: cfg.HTTPOnly,
		sameSite: sameSite,
		maxAge:   cfg.MaxAge,
	}
}

// SetRefreshToken sets the refresh token cookie.
func (m *Manager) SetRefreshToken(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.name,
		Value:    token,
		Path:     m.path,
		HttpOnly: m.httpOnly,
		Secure:   m.secure,
		SameSite: m.sameSite,
		MaxAge:   m.maxAge,
	})
}

// ClearRefreshToken clears the refresh token cookie.
func (m *Manager) ClearRefreshToken(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.name,
		Value:    "",
		Path:     m.path,
		MaxAge:   -1,
		HttpOnly: m.httpOnly,
		Secure:   m.secure,
		SameSite: m.sameSite,
	})
}

// GetRefreshToken retrieves the refresh token from the request.
func (m *Manager) GetRefreshToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(m.name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", errors.New("refresh token cookie not found")
		}
		return "", err
	}
	return cookie.Value, nil
}
