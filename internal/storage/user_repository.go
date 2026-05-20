package storage

import (
	"context"
	"time"

	"github.com/chilly266futon/auth-service/internal/domain"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetPermissionsByRoles(ctx context.Context, roles []string) ([]string, error)
	CountActiveUsers(ctx context.Context, since time.Duration) (int, error)
	CountAllUsers(ctx context.Context) (int, error)
	UpdateLastLogin(ctx context.Context, userID string, t time.Time) error
}

type EmailChecker interface {
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
}
