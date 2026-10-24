CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'analyst'))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON users TO {{ROLE_NAME}};
