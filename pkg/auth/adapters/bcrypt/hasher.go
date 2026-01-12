package bcrypt

import (
	"golang.org/x/crypto/bcrypt"
)

// Hasher implements ports.PasswordHasher using bcrypt.
type Hasher struct {
	cost int
}

// Option configures the Hasher.
type Option func(*Hasher)

// WithCost sets the bcrypt cost parameter.
func WithCost(cost int) Option {
	return func(h *Hasher) {
		h.cost = cost
	}
}

// New creates a new bcrypt Hasher.
func New(opts ...Option) *Hasher {
	h := &Hasher{
		cost: bcrypt.DefaultCost,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Hash generates a bcrypt hash from a plaintext password.
func (h *Hasher) Hash(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// Compare compares a plaintext password with a bcrypt hash.
func (h *Hasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
