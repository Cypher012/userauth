package session

import (
	"net/http"

	"github.com/Cypher012/userauth/internal/session"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func RegisterSession(r chi.Router, pool *pgxpool.Pool) {
	repo := session.NewSessionRepository(pool)
	service := session.NewSessionService(repo)
	handler := NewSessionHandler(service)

	r.Route("/v1/sessions", func(r chi.Router) {
		r.Post("/", handler.ListAllActiveSessionsHandler)                  //List all active sessions
		r.Post("/{id}", func(w http.ResponseWriter, r *http.Request) {})   //Get active session
		r.Delete("/{id}", func(w http.ResponseWriter, r *http.Request) {}) //Revoke one session (log out)
		r.Delete("/", func(w http.ResponseWriter, r *http.Request) {})     // Revoke all sessions
	})
}
