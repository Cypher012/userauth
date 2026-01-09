package main

import (
	"log"
	"time"

	"github.com/Cypher012/userauth/internal/auth"
	"github.com/Cypher012/userauth/internal/email"
	"github.com/Cypher012/userauth/internal/http/v1/authhttp"
	"github.com/Cypher012/userauth/internal/links"
	"github.com/Cypher012/userauth/internal/security"
	"github.com/Cypher012/userauth/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewRouter(pool *pgxpool.Pool, jwt *auth.JWTAuth) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(middleware.Heartbeat("/ok"))

	baseURL, err := security.GetEnv("API_BASE_URL")
	if err != nil {
		log.Fatal(err)
	}
	email_token_secret, err := security.GetEnv("EMAIL_TOKEN_SECRET")
	if err != nil {
		log.Fatal(err)
	}

	links := links.New(baseURL)
	emailSvc := email.EmailConfig(links)
	tokenSvc := token.TokenConfig(pool, email_token_secret)

	authModule := authhttp.NewModule(pool, tokenSvc, emailSvc, jwt)

	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Mount("/", authModule.Router)
	})

	return r
}
