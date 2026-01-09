package email

import (
	"log"
	"strconv"

	"github.com/Cypher012/userauth/internal/links"
	"github.com/Cypher012/userauth/internal/security"
)

func EmailConfig(links *links.Links) *EmailService {
	smtpPass, _ := security.GetEnv("BREVO_SMTP_PASS")
	port, _ := security.GetEnv("BREVO_SMTP_PORT")
	username, _ := security.GetEnv("BREVO_SMTP_USERNAME")
	host, _ := security.GetEnv("BREVO_SMTP_HOST")

	requiredEnvs := map[string]string{
		"BREVO_SMTP_PASS":     smtpPass,
		"BREVO_SMTP_PORT":     port,
		"BREVO_SMTP_USERNAME": username,
		"BREVO_SMTP_HOST":     host,
	}

	for name, value := range requiredEnvs {
		if value == "" {
			log.Fatalf("environment variable %s is not set", name)
		}
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		log.Fatal("BREVO_SMTP_PORT must be a valid number")
	}

	smtpMailer := NewSTMPMailer(host, portInt, username, smtpPass, "ayoojoade@gmail.com")

	templates, err := LoadTemplates()
	if err != nil {
		log.Fatal(err)
	}

	return NewService(smtpMailer, templates, links)
}
