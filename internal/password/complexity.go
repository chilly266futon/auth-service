package password

import (
	"regexp"
	"strings"
)

// Список абсурдных/популярных паролей
var absurdPasswords = map[string]struct{}{
	"password": {}, "123456": {}, "123456789": {}, "qwerty": {}, "abc123": {}, "111111": {}, "123123": {}, "12345": {}, "12345678": {}, "qwertyuiop": {}, "password1": {}, "admin": {}, "letmein": {}, "welcome": {}, "monkey": {}, "login": {}, "princess": {}, "dragon": {}, "football": {}, "iloveyou": {},
}

func CheckComplexity(password string) error {
	if len(password) < 8 {
		return ErrTooShort
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return ErrNoUpper
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return ErrNoLower
	}
	if !regexp.MustCompile(`\d`).MatchString(password) {
		return ErrNoDigit
	}
	if !regexp.MustCompile(`[!@#$%^&*()_+\-=[\]{};':",.<>/?]`).MatchString(password) {
		return ErrNoSpecial
	}
	return nil
}

func IsAbsurdPassword(password string) bool {
	_, found := absurdPasswords[strings.ToLower(password)]
	return found
}

var (
	ErrTooShort  = NewPasswordError("password too short (min 8 chars)")
	ErrNoUpper   = NewPasswordError("password must contain at least one uppercase letter")
	ErrNoLower   = NewPasswordError("password must contain at least one lowercase letter")
	ErrNoDigit   = NewPasswordError("password must contain at least one digit")
	ErrNoSpecial = NewPasswordError("password must contain at least one special character")
)

type PasswordError string

func (e PasswordError) Error() string { return string(e) }

func NewPasswordError(msg string) error { return PasswordError(msg) }
