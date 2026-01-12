package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// Generator implements ports.TokenGenerator.
type Generator struct {
	secret string
	prefix string
}

// New creates a new token Generator.
func New(secret string) *Generator {
	return &Generator{
		secret: secret,
		prefix: "etk",
	}
}

// Generate creates a new random token string.
func (g *Generator) Generate() (string, error) {
	const length = 32
	byteLen := (length * 3) / 4
	b := make([]byte, byteLen)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return g.prefix + base64.URLEncoding.EncodeToString(b)[:length], nil
}

// Hash creates an HMAC-SHA256 hash of the token.
func (g *Generator) Hash(token string) string {
	h := hmac.New(sha256.New, []byte(g.secret))
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
