// Package examples demonstrates how to integrate the auth module
// into different application architectures.
//
// This file is for documentation purposes and won't compile standalone.
// Copy the relevant sections into your application.
package examples

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/Cypher012/userauth/pkg/auth"
	"github.com/Cypher012/userauth/pkg/auth/adapters/bcrypt"
	"github.com/Cypher012/userauth/pkg/auth/adapters/cookie"
	"github.com/Cypher012/userauth/pkg/auth/adapters/jwt"
	"github.com/Cypher012/userauth/pkg/auth/adapters/postgres"
	"github.com/Cypher012/userauth/pkg/auth/adapters/smtp"
	"github.com/Cypher012/userauth/pkg/auth/adapters/token"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// =============================================================================
// EXAMPLE 1: New Go API (Minimal Setup)
// =============================================================================

func ExampleNewAPI() {
	// 1. Create database pool
	pool, _ := pgxpool.New(context.Background(), "postgres://...")

	// 2. Create auth config
	cfg := auth.DefaultConfig()
	cfg.JWTSecret = "your-jwt-secret"
	cfg.EmailTokenSecret = "your-email-token-secret"
	cfg.BaseURL = "https://api.yourapp.com"
	cfg.RoutePrefix = "/api/v1/auth"

	// 3. Create dependencies
	deps := auth.Dependencies{
		UserRepository:       postgres.NewUserRepository(pool),
		EmailTokenRepository: postgres.NewEmailTokenRepository(pool),
		PasswordHasher:       bcrypt.New(),
		TokenGenerator:       token.New(cfg.EmailTokenSecret),
		JWTProvider: jwt.New(
			cfg.JWTSecret,
			15*time.Minute,
			1*time.Hour,
		),
		CookieManager: cookie.New(cookie.Config{
			Name:     "refresh_token",
			Path:     "/",
			Secure:   true,
			HTTPOnly: true,
			SameSite: "lax",
			MaxAge:   3600,
		}),
		// Optional: Add email sender for verification emails
		// EmailSender: smtpSender,
	}

	// 4. Create auth module
	authModule, err := auth.New(cfg, deps)
	if err != nil {
		log.Fatal(err)
	}

	// 5. Create router and mount auth
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Mount("/api/v1/auth", authModule.Router())

	// 6. Use auth middleware on protected routes
	r.With(authModule.AccessMiddleware()).Get("/api/v1/profile", func(w http.ResponseWriter, r *http.Request) {
		claims, _ := authModule.JWTProvider().ExtractClaimsFromContext(r.Context())
		// Use claims.UserID to fetch user data
		_ = claims
	})

	http.ListenAndServe(":8080", r)
}

// =============================================================================
// EXAMPLE 2: Monolith with Multiple Modules
// =============================================================================

func ExampleMonolith() {
	pool, _ := pgxpool.New(context.Background(), "postgres://...")

	// Create auth module
	authModule := createAuthModule(pool)

	// Create main router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Mount auth at a specific path
	r.Mount("/auth", authModule.Router())

	// Mount other modules
	r.Route("/api", func(r chi.Router) {
		// Public routes
		r.Get("/health", healthHandler)

		// Protected routes - use auth middleware
		r.Group(func(r chi.Router) {
			r.Use(authModule.AccessMiddleware())

			r.Get("/users", listUsersHandler)
			r.Get("/orders", listOrdersHandler)
		})
	})

	http.ListenAndServe(":8080", r)
}

func createAuthModule(pool *pgxpool.Pool) *auth.Module {
	cfg := auth.DefaultConfig()
	cfg.JWTSecret = "secret"
	cfg.EmailTokenSecret = "email-secret"
	cfg.BaseURL = "https://myapp.com"

	deps := auth.Dependencies{
		UserRepository:       postgres.NewUserRepository(pool),
		EmailTokenRepository: postgres.NewEmailTokenRepository(pool),
		PasswordHasher:       bcrypt.New(),
		TokenGenerator:       token.New(cfg.EmailTokenSecret),
		JWTProvider:          jwt.New(cfg.JWTSecret, 15*time.Minute, 1*time.Hour),
		CookieManager: cookie.New(cookie.Config{
			Name: "refresh_token", Path: "/", Secure: true, HTTPOnly: true, SameSite: "lax", MaxAge: 3600,
		}),
	}

	module, _ := auth.New(cfg, deps)
	return module
}

// =============================================================================
// EXAMPLE 3: Microservice with Custom Adapters
// =============================================================================

func ExampleMicroservice() {
	pool, _ := pgxpool.New(context.Background(), "postgres://...")

	// Custom SMTP configuration
	emailSender, _ := smtp.New(smtp.Config{
		Host:     "smtp.sendgrid.net",
		Port:     587,
		Username: "apikey",
		Password: "your-sendgrid-key",
		From:     "noreply@yourservice.com",
	})

	// Custom bcrypt cost for stronger security
	hasher := bcrypt.New(bcrypt.WithCost(12))

	// Longer token TTLs for this service
	cfg := auth.DefaultConfig()
	cfg.JWTSecret = "microservice-jwt-secret"
	cfg.EmailTokenSecret = "microservice-email-secret"
	cfg.BaseURL = "https://auth.yourservice.com"
	cfg.AccessTokenTTL = 30 * time.Minute
	cfg.RefreshTokenTTL = 24 * time.Hour
	cfg.EmailTokenTTL = 2 * time.Hour

	deps := auth.Dependencies{
		UserRepository:       postgres.NewUserRepository(pool),
		EmailTokenRepository: postgres.NewEmailTokenRepository(pool),
		PasswordHasher:       hasher,
		TokenGenerator:       token.New(cfg.EmailTokenSecret),
		JWTProvider: jwt.New(
			cfg.JWTSecret,
			cfg.AccessTokenTTL,
			cfg.RefreshTokenTTL,
		),
		CookieManager: cookie.New(cookie.Config{
			Name:     "auth_refresh",
			Path:     "/",
			Secure:   true,
			HTTPOnly: true,
			SameSite: "strict", // Stricter for microservice
			MaxAge:   86400,    // 24 hours
		}),
		EmailSender: emailSender,
		Logger:      &customLogger{},
	}

	authModule, _ := auth.New(cfg, deps)

	r := chi.NewRouter()
	authModule.RegisterRoutes(r)
	http.ListenAndServe(":8080", r)
}

// =============================================================================
// EXAMPLE 4: Using Auth Service Directly (Without HTTP Handlers)
// =============================================================================

func ExampleDirectServiceUsage() {
	pool, _ := pgxpool.New(context.Background(), "postgres://...")

	cfg := auth.DefaultConfig()
	cfg.JWTSecret = "secret"
	cfg.EmailTokenSecret = "email-secret"
	cfg.BaseURL = "https://myapp.com"

	deps := auth.Dependencies{
		UserRepository:       postgres.NewUserRepository(pool),
		EmailTokenRepository: postgres.NewEmailTokenRepository(pool),
		PasswordHasher:       bcrypt.New(),
		TokenGenerator:       token.New(cfg.EmailTokenSecret),
		JWTProvider:          jwt.New(cfg.JWTSecret, 15*time.Minute, 1*time.Hour),
		CookieManager: cookie.New(cookie.Config{
			Name: "refresh_token", Path: "/", Secure: true, HTTPOnly: true, SameSite: "lax", MaxAge: 3600,
		}),
	}

	authModule, _ := auth.New(cfg, deps)

	// Use the service directly
	svc := authModule.AuthService()

	ctx := context.Background()

	// Register a user programmatically
	result, err := svc.RegisterUser(ctx, "user@example.com", "password123")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Created user: %s", result.User.ID)

	// Login
	user, err := svc.LoginUser(ctx, "user@example.com", "password123")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Logged in user: %s", user.Email)

	// Generate tokens
	accessToken, refreshToken, _ := authModule.JWTProvider().GenerateTokenPair(user.ID)
	log.Printf("Access token: %s", accessToken)
	log.Printf("Refresh token: %s", refreshToken)
}

// =============================================================================
// Helper Types for Examples
// =============================================================================

type customLogger struct{}

func (l *customLogger) Info(msg string, args ...any)  { log.Printf("[INFO] "+msg, args...) }
func (l *customLogger) Error(msg string, args ...any) { log.Printf("[ERROR] "+msg, args...) }
func (l *customLogger) Debug(msg string, args ...any) { log.Printf("[DEBUG] "+msg, args...) }

func healthHandler(w http.ResponseWriter, r *http.Request)     {}
func listUsersHandler(w http.ResponseWriter, r *http.Request)  {}
func listOrdersHandler(w http.ResponseWriter, r *http.Request) {}
