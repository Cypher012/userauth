package links

import "fmt"

func (l *Links) VerifyEmail(token string) string {
	return fmt.Sprintf("%s/auth/verify-email/%s", l.base, token)
}

func (l *Links) ForgetPassword(token string) string {
	return fmt.Sprintf("%s/auth/forget-password/%s", l.base, token)
}
