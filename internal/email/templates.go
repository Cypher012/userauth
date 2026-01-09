package email

import (
	"bytes"
	"html/template"
)

type Template struct {
	verify  *template.Template
	forget  *template.Template
	welcome *template.Template
}

func LoadTemplates() (*Template, error) {
	verify, err := template.ParseFiles("internal/email/templates/verify.html")
	if err != nil {
		return nil, err
	}
	forget, err := template.ParseFiles("internal/email/templates/forget.html")
	if err != nil {
		return nil, err
	}

	welcome, err := template.ParseFiles("internal/email/templates/welcome.html")
	if err != nil {
		return nil, err
	}

	return &Template{
		verify:  verify,
		forget:  forget,
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
