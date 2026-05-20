package validation

import (
	"context"
	"database/sql"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/chilly266futon/auth-service/internal/domain"
	"github.com/chilly266futon/auth-service/internal/dto/auth"
	"github.com/chilly266futon/auth-service/internal/storage"
)

func ValidateRegisterRequest(ctx context.Context, req auth.RegisterRequest, userStorage storage.EmailChecker) error {
	// email
	if req.Email == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}

	// email uniqueness
	existing, err := userStorage.GetByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		return status.Error(codes.AlreadyExists, domain.ErrEmailAlreadyExists.Error())
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return status.Error(codes.Internal, "failed to check email")
	}

	return nil
}
