-- +goose Up
CREATE TABLE users (
  id text PRIMARY KEY,
  email text UNIQUE NOT NULL,
  username text NOT NULL,
  password_hash text NOT NULL,
  roles text[] NOT NULL,
  created_at timestamp NOT NULL,
  updated_at timestamp NOT NULL
);

-- +goose Down
DROP TABLE users;