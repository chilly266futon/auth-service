package domain

import (
	"testing"
)

func TestNewJWTManager(t *testing.T) {
	manager := NewJWTManager("testsecret")
	if manager == nil {
		t.Error("JWTManager должен быть создан")
	}
}

func TestJWTManager_Generate(t *testing.T) {
	manager := NewJWTManager("testsecret")
	token, err := manager.Generate("user1", []string{"admin"}, []string{"read"})
	if err != nil {
		t.Errorf("Ошибка генерации токена: %v", err)
	}
	if token == "" {
		t.Error("Токен не должен быть пустым")
	}
}

func TestJWTManager_GenerateRefresh(t *testing.T) {
	manager := NewJWTManager("testsecret")
	token, err := manager.GenerateRefresh("user1", []string{"admin"}, []string{"read"})
	if err != nil {
		t.Errorf("Ошибка генерации refresh токена: %v", err)
	}
	if token == "" {
		t.Error("Refresh токен не должен быть пустым")
	}
}
