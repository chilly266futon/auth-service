package storage

import (
	"context"
	"time"
)

type TokenRepository interface {
	StoreRefreshToken(ctx context.Context, userID, token string, ttl time.Duration) error
	ValidateRefreshToken(ctx context.Context, userID, token string) error
	RevokeRefreshToken(ctx context.Context, userID, token string) error
	ReplaceRefreshToken(ctx context.Context, userID, oldToken, newToken string, ttl time.Duration) error
}
