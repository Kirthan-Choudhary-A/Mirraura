package main

import (
	"encoding/json"
	"fmt"
	"os"

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

func loadUsers() (map[string]User, error) {
	adminUser := os.Getenv("MIRRAURA_ADMIN_USER")
	adminPassword := os.Getenv("MIRRAURA_ADMIN_PASSWORD")
	if adminUser == "" || len(adminPassword) < 12 {
		return nil, fmt.Errorf("MIRRAURA_ADMIN_USER and MIRRAURA_ADMIN_PASSWORD (12+ chars) must both be set")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash admin password: %w", err)
	}

	users := map[string]User{
		adminUser: {Username: adminUser, PasswordHash: string(hash), Role: "admin"},
	}

	usersPath := os.Getenv("MIRRAURA_USERS_PATH")
	if usersPath == "" {
		return users, nil
	}
	data, err := os.ReadFile(usersPath)
	if os.IsNotExist(err) {
		return users, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", usersPath, err)
	}
	var entries []userJSONEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse %s: %w", usersPath, err)
	}
	for _, e := range entries {
		if e.Role != "admin" && e.Role != "analyst" {
			return nil, fmt.Errorf("%s: user %q has invalid role %q (must be admin or analyst)", usersPath, e.Username, e.Role)
		}
		if _, exists := users[e.Username]; exists {
			return nil, fmt.Errorf("%s: duplicate username %q", usersPath, e.Username)
		}
		users[e.Username] = User{Username: e.Username, PasswordHash: e.BcryptHash, Role: e.Role}
	}
	return users, nil
}
