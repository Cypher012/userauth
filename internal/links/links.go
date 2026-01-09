package links

import "fmt"

type Links struct {
	base string
}

func New(baseURL string) *Links {
	return &Links{
		base: fmt.Sprintf("%s/api/v1", baseURL),
	}
}
