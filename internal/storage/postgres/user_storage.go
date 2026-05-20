package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chilly266futon/auth-service/internal/domain"
)

type UserStorage struct {
	db *pgxpool.Pool
}

func NewUserStorage(pool *pgxpool.Pool) *UserStorage {
	return &UserStorage{
		db: pool,
	}
}

func (s *UserStorage) DB() *pgxpool.Pool {
	return s.db
}

func (s *UserStorage) Create(ctx context.Context, user *domain.User) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO users (id, email, username, password_hash, roles, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		user.ID, user.Email, user.Username, user.PasswordHash, user.Roles, user.CreatedAt, user.UpdatedAt,
	)

	return err
}

func (s *UserStorage) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	user := &domain.User{}
	err := s.db.QueryRow(ctx,
		`SELECT id, email, username, password_hash, roles, created_at, updated_at
			  FROM users WHERE email = $1`, email,
	).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.Roles, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserStorage) GetPermissionsByRoles(ctx context.Context, roles []string) ([]string, error) {
	if len(roles) == 0 {
		return nil, nil
	}

	rows, err := s.db.Query(ctx,
		"SELECT DISTINCT permission FROM role_permissions WHERE role = ANY($1)",
		roles,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	seen := make(map[string]bool)
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, err
		}
		if !seen[perm] {
			perms = append(perms, perm)
			seen[perm] = true
		}
	}

	return perms, nil
}

func (s *UserStorage) CountActiveUsers(ctx context.Context, since time.Duration) (int, error) {
	var count int
	sinceTime := time.Now().Add(-since)
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE updated_at >= $1`, sinceTime).Scan(&count)
	return count, err
}

func (s *UserStorage) CountAllUsers(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

func (s *UserStorage) UpdateLastLogin(ctx context.Context, userID string, t time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET updated_at = $1 WHERE id = $2`, t, userID)
	return err
}
