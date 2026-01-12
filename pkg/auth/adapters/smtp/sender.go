package smtp

import (
	"bytes"
	"embed"
	"html/template"

	"gopkg.in/gomail.v2"
)

//go:embed templates/*.html
var templateFS embed.FS

// Config holds SMTP configuration.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// Sender implements ports.EmailSender using SMTP.
type Sender struct {
	dialer    *gomail.Dialer
	from      string
	templates *templates
}

type templates struct {
	verify  *template.Template
	reset   *template.Template
	welcome *template.Template
}

// New creates a new SMTP Sender.
// If templateDir is empty, uses embedded templates.
func New(cfg Config) (*Sender, error) {
	dialer := gomail.NewDialer(cfg.Host, cfg.Port, cfg.Username, cfg.Password)

	tmpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}

	return &Sender{
		dialer:    dialer,
		from:      cfg.From,
		templates: tmpl,
	}, nil
}

// SendVerificationEmail sends an email verification link.
func (s *Sender) SendVerificationEmail(to, verifyURL string) error {
	html, err := render(s.templates.verify, map[string]string{
		"verify_email_url": verifyURL,
	})
	if err != nil {
		return err
	}

	return s.send(to, "Verify your email", html)
}

// SendPasswordResetEmail sends a password reset link.
func (s *Sender) SendPasswordResetEmail(to, resetURL string) error {
	html, err := render(s.templates.reset, map[string]string{
		"reset_password_url": resetURL,
	})
	if err != nil {
		return err
	}

	return s.send(to, "Reset your password", html)
}

// SendWelcomeEmail sends a welcome email.
func (s *Sender) SendWelcomeEmail(to string) error {
	html, err := render(s.templates.welcome, nil)
	if err != nil {
		return err
	}

	return s.send(to, "Welcome!", html)
}

func (s *Sender) send(to, subject, html string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", s.from)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", html)

	return s.dialer.DialAndSend(msg)
}

func loadTemplates() (*templates, error) {
	verify, err := template.ParseFS(templateFS, "templates/verify.html")
	if err != nil {
		return nil, err
	}

	reset, err := template.ParseFS(templateFS, "templates/reset.html")
	if err != nil {
		return nil, err
	}

	welcome, err := template.ParseFS(templateFS, "templates/welcome.html")
	if err != nil {
		return nil, err
	}

	return &templates{
		verify:  verify,
		reset:   reset,
		welcome: welcome,
	}, nil
}

func render(t *template.Template, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
