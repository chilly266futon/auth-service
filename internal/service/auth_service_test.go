package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/chilly266futon/auth-service/internal/domain"
	"github.com/chilly266futon/auth-service/internal/dto/auth"
)

type mockUserRepo struct{ mock.Mock }

func (m *mockUserRepo) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *mockUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*domain.User), args.Error(1)
}
func (m *mockUserRepo) GetPermissionsByRoles(ctx context.Context, roles []string) ([]string, error) {
	args := m.Called(ctx, roles)
	return args.Get(0).([]string), args.Error(1)
}
func (m *mockUserRepo) CountActiveUsers(ctx context.Context, since time.Duration) (int, error) {
	args := m.Called(ctx, since)
	return args.Int(0), args.Error(1)
}
func (m *mockUserRepo) CountAllUsers(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}
func (m *mockUserRepo) UpdateLastLogin(ctx context.Context, userID string, t time.Time) error {
	args := m.Called(ctx, userID, t)
	return args.Error(0)
}

type mockMetrics struct{ mock.Mock }

func (m *mockMetrics) IncRegistration(ctx context.Context, success bool) {
	m.Called(ctx, success)
}
func (m *mockMetrics) IncLogin(ctx context.Context, success bool)        { m.Called(ctx, success) }
func (m *mockMetrics) IncTokenRefresh(ctx context.Context, success bool) { m.Called(ctx, success) }
func (m *mockMetrics) SetActiveUsersGauge(ctx context.Context, value float64) {
	m.Called(ctx, value)
}
func (m *mockMetrics) SetUniqueRegistrationsGauge(ctx context.Context, value float64) {
	m.Called(ctx, value)
}

type mockTokenRepo struct{ mock.Mock }

func (m *mockTokenRepo) StoreRefreshToken(ctx context.Context, userID, token string, ttl time.Duration) error {
	args := m.Called(ctx, userID, token, ttl)
	return args.Error(0)
}
func (m *mockTokenRepo) ValidateRefreshToken(ctx context.Context, userID, token string) error {
	args := m.Called(ctx, userID, token)
	return args.Error(0)
}
func (m *mockTokenRepo) RevokeRefreshToken(ctx context.Context, userID, token string) error {
	args := m.Called(ctx, userID, token)
	return args.Error(0)
}
func (m *mockTokenRepo) ReplaceRefreshToken(ctx context.Context, userID, oldToken, newToken string, ttl time.Duration) error {
	args := m.Called(ctx, userID, oldToken, newToken, ttl)
	return args.Error(0)
}

// Мок jwtValidator
type mockJWTValidator struct{ mock.Mock }

func (m *mockJWTValidator) Validate(tokenString string) (*jwt.MapClaims, error) {
	args := m.Called(tokenString)
	return args.Get(0).(*jwt.MapClaims), args.Error(1)
}

func TestRegister_Success(t *testing.T) {
	userRepo := new(mockUserRepo)
	userRepo.On("Create", mock.Anything, mock.Anything).Return(nil)
	userRepo.On("GetByEmail", mock.Anything, mock.Anything).Return((*domain.User)(nil), nil)
	userRepo.On("CountAllUsers", mock.Anything).Return(0, nil)
	jwtManager := domain.NewJWTManager("testsecret")
	logger := zap.NewNop()
	metrics := new(mockMetrics)
	metrics.On("IncRegistration", mock.Anything, true).Return()
	metrics.On("SetUniqueRegistrationsGauge", mock.Anything, mock.Anything).Return()
	useCase := NewAuthUseCase(userRepo, nil, jwtManager, nil, metrics, logger)

	req := auth.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "Password123!",
	}
	resp, err := useCase.Register(context.Background(), req)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.UserID)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	userRepo := new(mockUserRepo)
	userRepo.On("GetByEmail", mock.Anything, "test@example.com").Return((*domain.User)(nil), assert.AnError)
	jwtManager := domain.NewJWTManager("testsecret")
	logger := zap.NewNop()
	metrics := new(mockMetrics)
	metrics.On("IncLogin", mock.Anything, false).Return()
	useCase := NewAuthUseCase(userRepo, nil, jwtManager, nil, metrics, logger)

	req := auth.LoginRequest{
		Email:    "test@example.com",
		Password: "Validpass123!",
	}
	resp, err := useCase.Login(context.Background(), req)
	assert.Error(t, err)
	assert.Empty(t, resp.UserID)
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	userRepo := new(mockUserRepo)
	tokenRepo := new(mockTokenRepo)
	jwtManager := domain.NewJWTManager("testsecret")
	jwtValidator := new(mockJWTValidator)
	jwtValidator.On("Validate", "badtoken").Return((*jwt.MapClaims)(nil), assert.AnError)
	metrics := new(mockMetrics)
	metrics.On("IncTokenRefresh", mock.Anything, false).Return()
	logger := zap.NewNop()
	useCase := NewAuthUseCase(userRepo, tokenRepo, jwtManager, jwtValidator, metrics, logger)

	req := auth.RefreshTokenRequest{RefreshToken: "badtoken"}
	resp, err := useCase.RefreshToken(context.Background(), req)
	assert.Error(t, err)
	assert.Empty(t, resp.UserID)
}

func TestValidateToken_InvalidToken(t *testing.T) {
	jwtValidator := new(mockJWTValidator)
	jwtValidator.On("Validate", "badtoken").Return((*jwt.MapClaims)(nil), assert.AnError)
	useCase := NewAuthUseCase(nil, nil, nil, jwtValidator, nil, zap.NewNop())

	req := auth.ValidateTokenRequest{Token: "badtoken"}
	resp, err := useCase.ValidateToken(req)
	assert.NoError(t, err)
	assert.False(t, resp.Valid)
}

func TestRefreshToken_Success(t *testing.T) {
	userRepo := new(mockUserRepo)
	userRepo.On("GetPermissionsByRoles", mock.Anything, mock.Anything).Return([]string{"perm1"}, nil)
	tokenRepo := new(mockTokenRepo)
	tokenRepo.On("ValidateRefreshToken", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	tokenRepo.On("StoreRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	tokenRepo.On("RevokeRefreshToken", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	jwtManager := domain.NewJWTManager("testsecret")
	jwtValidator := new(mockJWTValidator)
	claims := jwt.MapClaims{"sub": "user1", "roles": []interface{}{"role1"}}
	jwtValidator.On("Validate", "goodtoken").Return(&claims, nil)
	metrics := new(mockMetrics)
	metrics.On("IncTokenRefresh", mock.Anything, true).Return()
	logger := zap.NewNop()
	useCase := NewAuthUseCase(userRepo, tokenRepo, jwtManager, jwtValidator, metrics, logger)

	req := auth.RefreshTokenRequest{RefreshToken: "goodtoken"}
	resp, err := useCase.RefreshToken(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, "user1", resp.UserID)
	assert.True(t, len(resp.AccessToken) > 0)
	assert.True(t, len(resp.RefreshToken) > 0)
}

func TestValidateToken_Success(t *testing.T) {
	jwtValidator := new(mockJWTValidator)
	claims := jwt.MapClaims{"sub": "user1", "roles": []interface{}{"role1"}}
	jwtValidator.On("Validate", "goodtoken").Return(&claims, nil)
	useCase := NewAuthUseCase(nil, nil, nil, jwtValidator, nil, zap.NewNop())

	req := auth.ValidateTokenRequest{Token: "goodtoken"}
	resp, err := useCase.ValidateToken(req)
	assert.NoError(t, err)
	assert.True(t, resp.Valid)
	assert.Equal(t, "user1", resp.UserID)
	assert.Equal(t, []string{"role1"}, resp.Roles)
}

func TestRegister_ContextTimeout(t *testing.T) {
	userRepo := new(mockUserRepo)
	userRepo.On("GetByEmail", mock.Anything, "test@example.com").Return((*domain.User)(nil), context.DeadlineExceeded)
	jwtManager := domain.NewJWTManager("testsecret")
	logger := zap.NewNop()
	metrics := new(mockMetrics)
	metrics.On("IncRegistration", mock.Anything, false).Return()
	useCase := NewAuthUseCase(userRepo, nil, jwtManager, nil, metrics, logger)

	req := auth.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "Password123!",
	}
	resp, err := useCase.Register(context.Background(), req)
	assert.Error(t, err)
	// ошибка может быть обернута, поэтому проверяем только наличие ошибки
	assert.Empty(t, resp.UserID)
}

func TestLogin_ContextTimeout(t *testing.T) {
	userRepo := new(mockUserRepo)
	userRepo.On("GetByEmail", mock.Anything, "test@example.com").Return((*domain.User)(nil), context.DeadlineExceeded)
	jwtManager := domain.NewJWTManager("testsecret")
	logger := zap.NewNop()
	metrics := new(mockMetrics)
	metrics.On("IncLogin", mock.Anything, false).Return()
	useCase := NewAuthUseCase(userRepo, nil, jwtManager, nil, metrics, logger)

	req := auth.LoginRequest{
		Email:    "test@example.com",
		Password: "Password123!",
	}
	resp, err := useCase.Login(context.Background(), req)
	assert.Error(t, err)
	// ошибка может быть обернута, поэтому проверяем только наличие ошибки
	assert.Empty(t, resp.UserID)
}

func TestRefreshToken_ContextTimeout(t *testing.T) {
	userRepo := new(mockUserRepo)
	tokenRepo := new(mockTokenRepo)
	jwtManager := domain.NewJWTManager("testsecret")
	jwtValidator := new(mockJWTValidator)
	jwtValidator.On("Validate", "badtoken").Return((*jwt.MapClaims)(nil), context.DeadlineExceeded)
	metrics := new(mockMetrics)
	metrics.On("IncTokenRefresh", mock.Anything, false).Return()
	logger := zap.NewNop()
	useCase := NewAuthUseCase(userRepo, tokenRepo, jwtManager, jwtValidator, metrics, logger)

	req := auth.RefreshTokenRequest{RefreshToken: "badtoken"}
	resp, err := useCase.RefreshToken(context.Background(), req)
	assert.Error(t, err)
	// ошибка может быть обернута, поэтому проверяем только наличие ошибки
	assert.Empty(t, resp.UserID)
}
