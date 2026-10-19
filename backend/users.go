package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username     string
	PasswordHash string
	Role         string
}

type userJSONEntry struct {
	Username   string `json:"username"`
	BcryptHash string `json:"bcrypt_hash"`
	Role       string `json:"role"`
}

// SeedUsers inserts the env-seeded admin and any optional users.json entries
// into the users table, but only when the table is completely empty -- a
// one-time bootstrap, not a continuous reload. Once any user exists, the
// runtime admin UI is the only way to manage users, so a runtime action
// (promote/demote/remove, including removing the bootstrap admin) survives
// a restart instead of being silently undone.
func SeedUsers(ctx context.Context, pool *pgxpool.Pool) error {
	adminUser := os.Getenv("MIRRAURA_ADMIN_USER")
	adminPassword := os.Getenv("MIRRAURA_ADMIN_PASSWORD")
	if adminUser == "" {
		return fmt.Errorf("MIRRAURA_ADMIN_USER must be set")
	}
	if len(adminPassword) < 12 {
		return fmt.Errorf("MIRRAURA_ADMIN_PASSWORD must be at least 12 characters")
	}
	var existing int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&existing); err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if existing > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	if err := upsertUserIfAbsent(ctx, pool, adminUser, string(hash), "admin"); err != nil {
		return fmt.Errorf("seed admin: %w", err)
	}

	usersPath := os.Getenv("MIRRAURA_USERS_PATH")
	if usersPath == "" {
		return nil
	}
	data, err := os.ReadFile(usersPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", usersPath, err)
	}
	var entries []userJSONEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parse %s: %w", usersPath, err)
	}
	for _, e := range entries {
		if e.Role != "admin" && e.Role != "analyst" {
			return fmt.Errorf("%s: user %q has invalid role %q (must be admin or analyst)", usersPath, e.Username, e.Role)
		}
		if err := upsertUserIfAbsent(ctx, pool, e.Username, e.BcryptHash, e.Role); err != nil {
			return fmt.Errorf("seed %s: %w", e.Username, err)
		}
	}
	return nil
}

func upsertUserIfAbsent(ctx context.Context, pool *pgxpool.Pool, username, passwordHash, role string) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING`,
		username, passwordHash, role,
	)
	return err
}

func GetUser(ctx context.Context, pool *pgxpool.Pool, username string) (User, error) {
	var u User
	u.Username = username
	err := pool.QueryRow(ctx, `SELECT password_hash, role FROM users WHERE username = $1`, username).Scan(&u.PasswordHash, &u.Role)
	return u, err
}

func ListUsers(ctx context.Context, pool *pgxpool.Pool) ([]User, error) {
	rows, err := pool.Query(ctx, `SELECT username, password_hash, role FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.PasswordHash, &u.Role); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}
