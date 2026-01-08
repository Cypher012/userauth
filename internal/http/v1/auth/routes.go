package auth

import (
	"net/http"

	"github.com/Cypher012/userauth/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func RegisterAuth(r chi.Router, pool *pgxpool.Pool) {
	repo := auth.NewAuthRepository(pool)
	service := auth.NewAuthService(repo)
	handler := NewAuthHandler(service)

	r.Route("/v1/auth", func(r chi.Router) {
		r.Post("/signup", handler.SignUpUserHandler)
		r.Post("/login", func(w http.ResponseWriter, r *http.Request) {})
		r.Post("/verify-email", func(w http.ResponseWriter, r *http.Request) {})
		r.Post("/forget-password", func(w http.ResponseWriter, r *http.Request) {})
		r.Post("/token-refresh", func(w http.ResponseWriter, r *http.Request) {})
	})
}
