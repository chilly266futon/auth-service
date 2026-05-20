package validation

import (
	"context"
	"database/sql"
	"testing"

	"github.com/chilly266futon/auth-service/internal/domain"
	"github.com/chilly266futon/auth-service/internal/dto/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockEmailChecker struct{ mock.Mock }

func (m *mockEmailChecker) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*domain.User), args.Error(1)
}

func TestValidateRegisterRequest_EmailRequired(t *testing.T) {
	checker := new(mockEmailChecker)
	req := auth.RegisterRequest{Email: "", Username: "user", Password: "pass"}
	err := ValidateRegisterRequest(context.Background(), req, checker)
	assert.Error(t, err)
}

func TestValidateRegisterRequest_EmailExists(t *testing.T) {
	checker := new(mockEmailChecker)
	checker.On("GetByEmail", mock.Anything, "test@example.com").Return(&domain.User{}, nil)
	req := auth.RegisterRequest{Email: "test@example.com", Username: "user", Password: "pass"}
	err := ValidateRegisterRequest(context.Background(), req, checker)
	assert.Error(t, err)
}

func TestValidateRegisterRequest_Ok(t *testing.T) {
	checker := new(mockEmailChecker)
	checker.On("GetByEmail", mock.Anything, "new@example.com").Return((*domain.User)(nil), sql.ErrNoRows)
	req := auth.RegisterRequest{Email: "new@example.com", Username: "user", Password: "pass"}
	err := ValidateRegisterRequest(context.Background(), req, checker)
	assert.NoError(t, err)
}
