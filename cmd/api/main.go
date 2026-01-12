package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Cypher012/userauth/internal/db"
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
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file (optional in production)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Load configuration
	cfg := loadConfig()

	// Connect to database
	ctx := context.Background()
	pool := db.NewDB(ctx)
	defer pool.Close()

	// Create auth module
	authModule, err := createAuthModule(cfg, pool)
	if err != nil {
		log.Fatalf("Failed to create auth module: %v", err)
	}

	// Create router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(middleware.Heartbeat("/ok"))

	// Mount auth routes
	r.Mount("/api/v1/auth", authModule.Router())

	// Example: Protected route using auth middleware
	r.With(authModule.AccessMiddleware()).Get("/api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		claims, err := authModule.JWTProvider().ExtractClaimsFromContext(r.Context())
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user_id":"` + claims.UserID + `"}`))
	})

	log.Printf("Server starting on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, r); err != nil {
		log.Fatal(err)
	}
}

// AppConfig holds all application configuration.
type AppConfig struct {
	Port             string
	BaseURL          string
	JWTSecret        string
	EmailTokenSecret string

	// SMTP
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
}

func loadConfig() AppConfig {
	smtpPort, _ := strconv.Atoi(getEnv("BREVO_SMTP_PORT", "587"))

	return AppConfig{
		Port:             getEnv("PORT", "8080"),
		BaseURL:          mustGetEnv("API_BASE_URL"),
		JWTSecret:        mustGetEnv("JWT_SECRET"),
		EmailTokenSecret: mustGetEnv("EMAIL_TOKEN_SECRET"),

		SMTPHost:     getEnv("BREVO_SMTP_HOST", ""),
		SMTPPort:     smtpPort,
		SMTPUsername: getEnv("BREVO_SMTP_USERNAME", ""),
		SMTPPassword: getEnv("BREVO_SMTP_PASS", ""),
		SMTPFrom:     getEnv("SMTP_FROM", "noreply@example.com"),
	}
}

func createAuthModule(cfg AppConfig, pool *pgxpool.Pool) (*auth.Module, error) {
	// Create adapters
	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewEmailTokenRepository(pool)
	hasher := bcrypt.New()
	tokenGen := token.New(cfg.EmailTokenSecret)

	jwtProvider := jwt.New(
		cfg.JWTSecret,
		15*time.Minute, // Access token TTL
		1*time.Hour,    // Refresh token TTL
	)

	cookieManager := cookie.New(cookie.Config{
		Name:     "refresh_token",
		Path:     "/",
		Secure:   true,
		HTTPOnly: true,
		SameSite: "lax",
		MaxAge:   3600, // 1 hour
	})

	// Create email sender (optional)
	var emailSender *smtp.Sender
	if cfg.SMTPHost != "" {
		var err error
		emailSender, err = smtp.New(smtp.Config{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
		})
		if err != nil {
			log.Printf("Warning: Email sender not configured: %v", err)
		}
	}

	// Create auth config
	authCfg := auth.DefaultConfig()
	authCfg.JWTSecret = cfg.JWTSecret
	authCfg.EmailTokenSecret = cfg.EmailTokenSecret
	authCfg.BaseURL = cfg.BaseURL
	authCfg.RoutePrefix = "/api/v1/auth"

	// Create auth module
	return auth.New(authCfg, auth.Dependencies{
		UserRepository:       userRepo,
		EmailTokenRepository: tokenRepo,
		PasswordHasher:       hasher,
		TokenGenerator:       tokenGen,
		JWTProvider:          jwtProvider,
		CookieManager:        cookieManager,
		EmailSender:          emailSender,
		Logger:               &stdLogger{},
	})
}

// stdLogger is a simple logger implementation.
type stdLogger struct{}

func (l *stdLogger) Info(msg string, args ...any) {
	log.Printf("[INFO] "+msg, args...)
}

func (l *stdLogger) Error(msg string, args ...any) {
	log.Printf("[ERROR] "+msg, args...)
}

func (l *stdLogger) Debug(msg string, args ...any) {
	log.Printf("[DEBUG] "+msg, args...)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Required environment variable %s is not set", key)
	}
	return value
}
