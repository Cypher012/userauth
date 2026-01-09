package email

import (
	"log"

	"github.com/Cypher012/userauth/internal/links"
)

type EmailService struct {
	sender    Sender
	templates *Template
	links     *links.Links
}

func NewService(sender Sender, templates *Template, links *links.Links) *EmailService {
	return &EmailService{
		sender:    sender,
		templates: templates,
		links:     links,
	}
}

func (s *EmailService) SendWelcomeEmail(to string) error {
	html, err := render(s.templates.welcome, nil)
	if err != nil {
		return err
	}
	return s.sender.Send(to, "Welcome to my app", html)
}

func (s *EmailService) SendVerifyEmail(to, token string) error {
	verifyEmailURL := s.links.VerifyEmail(token)
	log.Println(to)
	log.Println(verifyEmailURL)
	html, err := render(s.templates.verify, map[string]string{
		"verify_email_url": verifyEmailURL,
	})
	if err != nil {
		return err
	}
	return s.sender.Send(to, "Verify your email", html)
}

func (s *EmailService) SendForgetPasswordEmail(to, token string) error {
	forgetPasswordURL := s.links.ForgetPassword(token)
	html, err := render(s.templates.forget, map[string]string{
		"forget_password_url": forgetPasswordURL,
	})
	if err != nil {
		return err
	}
	return s.sender.Send(to, "Reset your password", html)
}
