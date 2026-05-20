-- +goose Up
CREATE TABLE role_permissions (
  role text NOT NULL,
  permission text NOT NULL,
  PRIMARY KEY (role, permission)
);

-- Начальные данные (можно менять в админке позже)
INSERT INTO role_permissions (role, permission) VALUES
  ('COMMON', 'view:market'),
  ('COMMON', 'trade:spot'),
  ('VERIFIED', 'trade:spot'),
  ('VERIFIED', 'view:market:private'),
  ('PREMIUM', 'trade:spot'),
  ('PREMIUM', 'trade:futures'),
  ('PREMIUM', 'view:market:private'),
  ('ADMIN', 'trade:spot'),
  ('ADMIN', 'trade:futures'),
  ('ADMIN', 'admin:delete_user'),
  ('ADMIN', 'admin:manage_markets');

-- +goose Down
DROP TABLE role_permissions;