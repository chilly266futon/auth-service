package password

import "testing"

func TestCheckComplexity(t *testing.T) {
	cases := []struct {
		pass string
		ok   bool
	}{
		{"Qwerty1!", true},
		{"qwerty1!", false}, // нет заглавной
		{"QWERTY1!", false}, // нет строчной
		{"Qwerty!!", false}, // нет цифры
		{"Qwerty11", false}, // нет спецсимвола
		{"Q1!", false},      // короткий
	}
	for _, c := range cases {
		err := CheckComplexity(c.pass)
		if (err == nil) != c.ok {
			t.Errorf("CheckComplexity(%q) = %v, want ok=%v", c.pass, err, c.ok)
		}
	}
}

func TestIsAbsurdPassword(t *testing.T) {
	if !IsAbsurdPassword("password") {
		t.Error("password должен считаться абсурдным")
	}
	if IsAbsurdPassword("Qwerty1!") {
		t.Error("Qwerty1! не должен считаться абсурдным")
	}
}
