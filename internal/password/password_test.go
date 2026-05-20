package password

import (
	"testing"
)

func TestHashAndCheck(t *testing.T) {
	pass := "mySecret123"
	hash, err := Hash(pass)
	if err != nil {
		t.Fatalf("Ошибка хеширования: %v", err)
	}
	if !Check(hash, pass) {
		t.Error("Check должен возвращать true для корректного пароля")
	}
	if Check(hash, "wrong") {
		t.Error("Check должен возвращать false для некорректного пароля")
	}
}
