-- +goose Up
CREATE INDEX idx_users_username ON users(username);

-- +goose Down
DROP INDEX idx_users_username;
