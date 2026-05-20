package grpc

import (
	"context"
	"testing"

	"github.com/chilly266futon/auth-service/internal/dto/auth"
	pb "github.com/chilly266futon/exchange-service-contracts/gen/pb/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockAuthService struct{ mock.Mock }

func (m *mockAuthService) Register(ctx context.Context, req auth.RegisterRequest) (auth.RegisterResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(auth.RegisterResponse), args.Error(1)
}
func (m *mockAuthService) Login(ctx context.Context, req auth.LoginRequest) (auth.LoginResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(auth.LoginResponse), args.Error(1)
}
func (m *mockAuthService) RefreshToken(ctx context.Context, req auth.RefreshTokenRequest) (auth.RefreshTokenResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(auth.RefreshTokenResponse), args.Error(1)
}
func (m *mockAuthService) ValidateToken(req auth.ValidateTokenRequest) (auth.ValidateTokenResponse, error) {
	args := m.Called(req)
	return args.Get(0).(auth.ValidateTokenResponse), args.Error(1)
}

func TestRegister_Success(t *testing.T) {
	mockSvc := new(mockAuthService)
	server := NewAuthServer(mockSvc)
	pbReq := &pb.RegisterRequest{Email: "test@example.com", Password: "pass", Username: "user"}
	mockSvc.On("Register", mock.Anything, auth.RegisterRequest{Email: "test@example.com", Password: "pass", Username: "user"}).Return(auth.RegisterResponse{UserID: "u1"}, nil)
	resp, err := server.Register(context.Background(), pbReq)
	assert.NoError(t, err)
	assert.Equal(t, "u1", resp.UserId)
}

func TestRegister_Error(t *testing.T) {
	mockSvc := new(mockAuthService)
	server := NewAuthServer(mockSvc)
	pbReq := &pb.RegisterRequest{Email: "test@example.com", Password: "pass", Username: "user"}
	mockSvc.On("Register", mock.Anything, auth.RegisterRequest{Email: "test@example.com", Password: "pass", Username: "user"}).Return(auth.RegisterResponse{}, assert.AnError)
	resp, err := server.Register(context.Background(), pbReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestLogin_Success(t *testing.T) {
	mockSvc := new(mockAuthService)
	server := NewAuthServer(mockSvc)
	pbReq := &pb.LoginRequest{Email: "test@example.com", Password: "pass"}
	mockSvc.On("Login", mock.Anything, auth.LoginRequest{Email: "test@example.com", Password: "pass"}).Return(auth.LoginResponse{AccessToken: "a", RefreshToken: "r", UserID: "u1", Roles: []string{"admin"}}, nil)
	resp, err := server.Login(context.Background(), pbReq)
	assert.NoError(t, err)
	assert.Equal(t, "a", resp.AccessToken)
	assert.Equal(t, "r", resp.RefreshToken)
	assert.Equal(t, "u1", resp.UserId)
	assert.Equal(t, []string{"admin"}, resp.Roles)
}

func TestLogin_Error(t *testing.T) {
	mockSvc := new(mockAuthService)
	server := NewAuthServer(mockSvc)
	pbReq := &pb.LoginRequest{Email: "test@example.com", Password: "pass"}
	mockSvc.On("Login", mock.Anything, auth.LoginRequest{Email: "test@example.com", Password: "pass"}).Return(auth.LoginResponse{}, assert.AnError)
	resp, err := server.Login(context.Background(), pbReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestRefreshToken_Success(t *testing.T) {
	mockSvc := new(mockAuthService)
	server := NewAuthServer(mockSvc)
	pbReq := &pb.RefreshTokenRequest{RefreshToken: "r"}
	mockSvc.On("RefreshToken", mock.Anything, auth.RefreshTokenRequest{RefreshToken: "r"}).Return(auth.RefreshTokenResponse{AccessToken: "a", RefreshToken: "r2", UserID: "u1", Roles: []string{"admin"}}, nil)
	resp, err := server.RefreshToken(context.Background(), pbReq)
	assert.NoError(t, err)
	assert.Equal(t, "a", resp.AccessToken)
	assert.Equal(t, "r2", resp.RefreshToken)
	assert.Equal(t, "u1", resp.UserId)
	assert.Equal(t, []string{"admin"}, resp.Roles)
}

func TestRefreshToken_Error(t *testing.T) {
	mockSvc := new(mockAuthService)
	server := NewAuthServer(mockSvc)
	pbReq := &pb.RefreshTokenRequest{RefreshToken: "r"}
	mockSvc.On("RefreshToken", mock.Anything, auth.RefreshTokenRequest{RefreshToken: "r"}).Return(auth.RefreshTokenResponse{}, assert.AnError)
	resp, err := server.RefreshToken(context.Background(), pbReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestValidateToken_Success(t *testing.T) {
	mockSvc := new(mockAuthService)
	server := NewAuthServer(mockSvc)
	pbReq := &pb.ValidateTokenRequest{Token: "t"}
	mockSvc.On("ValidateToken", auth.ValidateTokenRequest{Token: "t"}).Return(auth.ValidateTokenResponse{UserID: "u1", Roles: []string{"admin"}, Valid: true}, nil)
	resp, err := server.ValidateToken(context.Background(), pbReq)
	assert.NoError(t, err)
	assert.Equal(t, "u1", resp.UserId)
	assert.Equal(t, []string{"admin"}, resp.Roles)
	assert.True(t, resp.Valid)
}

func TestValidateToken_Error(t *testing.T) {
	mockSvc := new(mockAuthService)
	server := NewAuthServer(mockSvc)
	pbReq := &pb.ValidateTokenRequest{Token: "t"}
	mockSvc.On("ValidateToken", auth.ValidateTokenRequest{Token: "t"}).Return(auth.ValidateTokenResponse{}, assert.AnError)
	resp, err := server.ValidateToken(context.Background(), pbReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
}
