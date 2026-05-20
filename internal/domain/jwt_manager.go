package domain

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	secret []byte
}

func NewJWTManager(secret string) *JWTManager {
	return &JWTManager{secret: []byte(secret)}
}

func (m *JWTManager) Generate(userID string, roles, permissions []string) (string, error) {
	claims := jwt.MapClaims{
		"sub":         userID,
		"roles":       roles,
		"permissions": permissions,
		"exp":         time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *JWTManager) GenerateRefresh(userID string, roles, permissions []string) (string, error) {
	claims := jwt.MapClaims{
		"sub":         userID,
		"roles":       roles,
		"permissions": permissions,
		"exp":         time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}
