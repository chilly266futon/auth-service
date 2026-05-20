package service

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/chilly266futon/auth-service/internal/domain"
	"github.com/chilly266futon/auth-service/internal/dto/auth"
	"github.com/chilly266futon/auth-service/internal/password"
	"github.com/chilly266futon/auth-service/internal/storage"
	"github.com/chilly266futon/auth-service/internal/validation"
	"github.com/chilly266futon/exchange-shared/pkg/interceptors"
)

type AuthService interface {
	Register(ctx context.Context, req auth.RegisterRequest) (auth.RegisterResponse, error)
	Login(ctx context.Context, req auth.LoginRequest) (auth.LoginResponse, error)
	RefreshToken(ctx context.Context, req auth.RefreshTokenRequest) (auth.RefreshTokenResponse, error)
	ValidateToken(req auth.ValidateTokenRequest) (auth.ValidateTokenResponse, error)
}

type AuthMetrics interface {
	IncRegistration(ctx context.Context, success bool)
	IncLogin(ctx context.Context, success bool)
	IncTokenRefresh(ctx context.Context, success bool)
	SetActiveUsersGauge(ctx context.Context, value float64)
	SetUniqueRegistrationsGauge(ctx context.Context, value float64)
}

type JWTValidator interface {
	Validate(tokenString string) (*jwt.MapClaims, error)
}

type JWTManager interface {
	Generate(userID string, roles, permissions []string) (string, error)
	GenerateRefresh(userID string, roles, permissions []string) (string, error)
}

type AuthUseCase struct {
	userRepo     storage.UserRepository
	tokenRepo    storage.TokenRepository
	jwtManager   JWTManager
	jwtValidator JWTValidator
	metrics      AuthMetrics
	logger       *zap.Logger
}

func NewAuthUseCase(
	userRepo storage.UserRepository,
	tokenRepo storage.TokenRepository,
	jwtManager JWTManager,
	jwtValidator JWTValidator,
	metrics AuthMetrics,
	logger *zap.Logger,
) *AuthUseCase {
	return &AuthUseCase{
		userRepo:     userRepo,
		tokenRepo:    tokenRepo,
		jwtManager:   jwtManager,
		jwtValidator: jwtValidator,
		metrics:      metrics,
		logger:       logger,
	}
}

func (s *AuthUseCase) Register(ctx context.Context, req auth.RegisterRequest) (auth.RegisterResponse, error) {
	traceID := interceptors.GetTraceID(ctx)
	// Валидация входных данных
	if err := validation.ValidateRegisterRequest(ctx, req, s.userRepo); err != nil {
		s.logger.Warn("registration validation failed",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return auth.RegisterResponse{}, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	hash, err := password.Hash(req.Password)
	if err != nil {
		s.logger.Error("failed to hash password",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return auth.RegisterResponse{}, status.Error(codes.Internal, "failed to hash password")
	}

	user := &domain.User{
		ID:           uuid.NewString(),
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: hash,
		Roles:        []string{"COMMON"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Проверка сложности пароля
	if err := password.CheckComplexity(req.Password); err != nil {
		s.logger.Warn("password complexity check failed",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return auth.RegisterResponse{}, status.Errorf(codes.InvalidArgument, "password: %v", err)
	}
	// Проверка на абсурдный пароль
	if password.IsAbsurdPassword(req.Password) {
		s.logger.Warn("absurd password detected",
			zap.String("trace_id", traceID),
			zap.String("password", req.Password))
		return auth.RegisterResponse{}, status.Errorf(codes.InvalidArgument, "password is too common or absurd")
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.Error("failed to create user",
			zap.String("trace_id", traceID),
			zap.Error(err))
		s.metrics.IncRegistration(ctx, false)
		return auth.RegisterResponse{}, status.Error(codes.Internal, "failed to register")
	}

	// Обновляем метрику уникальных регистраций
	s.updateUniqueRegistrationsGauge(ctx)

	s.metrics.IncRegistration(ctx, true)
	s.logger.Info("user registered successfully",
		zap.String("trace_id", traceID),
		zap.String("user_id", user.ID),
		zap.String("email", user.Email))

	return auth.RegisterResponse{UserID: user.ID}, nil
}

func (s *AuthUseCase) Login(ctx context.Context, req auth.LoginRequest) (auth.LoginResponse, error) {
	traceID := interceptors.GetTraceID(ctx)
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil || user == nil {
		s.metrics.IncLogin(ctx, false)
		s.logger.Info("login failed",
			zap.String("trace_id", traceID),
			zap.String("email", req.Email),
			zap.String("reason", "user not found"))
		return auth.LoginResponse{}, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	if !password.Check(user.PasswordHash, req.Password) {
		s.metrics.IncLogin(ctx, false)
		s.logger.Info("login failed",
			zap.String("trace_id", traceID),
			zap.String("email", req.Email),
			zap.String("reason", "wrong password"),
			zap.String("user_id", user.ID))
		return auth.LoginResponse{}, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	permissions, err := s.userRepo.GetPermissionsByRoles(ctx, user.Roles)
	if err != nil {
		s.logger.Error("failed to get permissions",
			zap.String("trace_id", traceID),
			zap.Error(err),
			zap.String("user_id", user.ID))
		return auth.LoginResponse{}, status.Error(codes.Internal, "failed to get permissions")
	}

	accessToken, err := s.jwtManager.Generate(user.ID, user.Roles, permissions)
	if err != nil {
		s.logger.Error("failed to generate access token",
			zap.String("trace_id", traceID),
			zap.String("user_id", user.ID),
			zap.Error(err))
		return auth.LoginResponse{}, status.Error(codes.Internal, "failed to generate token")
	}

	refreshToken, err := s.jwtManager.GenerateRefresh(user.ID, user.Roles, permissions)
	if err != nil {
		s.logger.Error("failed to generate refresh token",
			zap.String("trace_id", traceID),
			zap.String("user_id", user.ID),
			zap.Error(err))
		return auth.LoginResponse{}, status.Error(codes.Internal, "failed to generate token")
	}

	err = s.tokenRepo.StoreRefreshToken(ctx, user.ID, refreshToken, 7*24*time.Hour)
	if err != nil {
		s.logger.Error("failed to store refresh token",
			zap.String("trace_id", traceID),
			zap.String("user_id", user.ID),
			zap.Error(err))
		return auth.LoginResponse{}, status.Error(codes.Internal, "failed to store token")
	}

	// Обновляем время последнего логина пользователя
	_ = s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now())
	// Обновляем метрику активных пользователей
	s.updateActiveUsersGauge(ctx)

	s.metrics.IncLogin(ctx, true)
	s.logger.Info("login success",
		zap.String("trace_id", traceID),
		zap.String("user_id", user.ID),
		zap.String("email", user.Email))

	return auth.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Roles:        user.Roles,
	}, nil
}

func (s *AuthUseCase) RefreshToken(ctx context.Context, req auth.RefreshTokenRequest) (auth.RefreshTokenResponse, error) {
	traceID := interceptors.GetTraceID(ctx)
	claims, err := s.jwtValidator.Validate(req.RefreshToken)
	// если токен не валиден, возвращаем ошибку
	if err != nil || claims == nil {
		s.logger.Warn("refresh token validation failed",
			zap.String("trace_id", traceID),
			zap.Error(err))
		return auth.RefreshTokenResponse{}, domain.ErrInvalidRefreshToken
	}

	userID, _ := (*claims)["sub"].(string)
	roles := parseStringSliceFromClaims(*claims, "roles")

	// Проверяем, что refresh токен все еще валиден (не отозван)
	err = s.tokenRepo.ValidateRefreshToken(ctx, userID, req.RefreshToken)
	if err != nil {
		s.metrics.IncTokenRefresh(ctx, false)
		s.logger.Warn("refresh token invalid or revoked",
			zap.String("trace_id", traceID),
			zap.String("user_id", userID),
			zap.Error(err))
		return auth.RefreshTokenResponse{}, domain.ErrInvalidRefreshToken
	}

	perms, err := s.userRepo.GetPermissionsByRoles(ctx, roles)
	if err != nil {
		s.metrics.IncTokenRefresh(ctx, false)
		s.logger.Error("failed to get permissions for roles",
			zap.String("trace_id", traceID),
			zap.String("user_id", userID),
			zap.Strings("roles", roles),
			zap.Error(err))
		return auth.RefreshTokenResponse{}, status.Error(codes.Internal, "failed to get permissions")
	}

	newAccessToken, err := s.jwtManager.Generate(userID, roles, perms)
	if err != nil {
		s.logger.Error("failed to generate new access token",
			zap.String("trace_id", traceID),
			zap.String("user_id", userID),
			zap.Error(err))
		return auth.RefreshTokenResponse{}, status.Error(codes.Internal, "failed to generate token")
	}

	newRefreshToken, err := s.jwtManager.GenerateRefresh(userID, roles, perms)
	if err != nil {
		s.logger.Error("failed to generate new refresh token",
			zap.String("trace_id", traceID),
			zap.String("user_id", userID),
			zap.Error(err))
		return auth.RefreshTokenResponse{}, status.Error(codes.Internal, "failed to generate token")
	}

	if err = s.tokenRepo.ReplaceRefreshToken(ctx, userID, req.RefreshToken, newRefreshToken, 7*24*time.Hour); err != nil {
		s.metrics.IncTokenRefresh(ctx, false)
		if err.Error() == "old token not found" {
			s.logger.Warn("refresh token invalid or revoked during replacement",
				zap.String("trace_id", traceID),
				zap.String("user_id", userID),
				zap.Error(err))
			return auth.RefreshTokenResponse{}, domain.ErrInvalidRefreshToken
		}
		s.logger.Error("failed to replace refresh token",
			zap.String("trace_id", traceID),
			zap.String("user_id", userID),
			zap.Error(err))
		return auth.RefreshTokenResponse{}, status.Error(codes.Internal, "token rotation failed")
	}

	s.metrics.IncTokenRefresh(ctx, true)
	s.logger.Info("token refreshed successfully",
		zap.String("trace_id", traceID),
		zap.String("user_id", userID))

	return auth.RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		UserID:       userID,
		Roles:        roles,
	}, nil
}

func (s *AuthUseCase) ValidateToken(req auth.ValidateTokenRequest) (auth.ValidateTokenResponse, error) {
	claims, err := s.jwtValidator.Validate(req.Token)
	if err != nil || claims == nil {
		s.logger.Debug("token validation failed",
			zap.Error(err))
		return auth.ValidateTokenResponse{Valid: false}, nil
	}

	userID, _ := (*claims)["sub"].(string)
	roles := parseStringSliceFromClaims(*claims, "roles")

	s.logger.Debug("token validated successfully",
		zap.String("user_id", userID),
		zap.Strings("roles", roles))

	return auth.ValidateTokenResponse{
		UserID: userID,
		Roles:  roles,
		Valid:  true,
	}, nil
}

func (s *AuthUseCase) updateActiveUsersGauge(ctx context.Context) {
	// Получаем количество уникальных пользователей, залогинившихся за последние 15 минут
	count, err := s.userRepo.CountActiveUsers(ctx, 15*time.Minute)
	if err == nil {
		s.metrics.SetActiveUsersGauge(ctx, float64(count))
	}
}

func (s *AuthUseCase) updateUniqueRegistrationsGauge(ctx context.Context) {
	count, err := s.userRepo.CountAllUsers(ctx)
	if err == nil {
		s.metrics.SetUniqueRegistrationsGauge(ctx, float64(count))
	}
}

// Хелпер для извлечения []string из jwt.MapClaims
func parseStringSliceFromClaims(claims jwt.MapClaims, key string) []string {
	val, ok := claims[key]
	if !ok {
		return nil
	}
	arr, ok := val.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
