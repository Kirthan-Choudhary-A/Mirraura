package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func listUsersHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := ListUsers(r.Context(), pool)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		type userView struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		views := make([]userView, 0, len(users))
		for _, u := range users {
			views = append(views, userView{Username: u.Username, Role: u.Role})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(views)
	}
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func createUserHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Role != "admin" && req.Role != "analyst" {
			http.Error(w, "role must be admin or analyst", http.StatusBadRequest)
			return
		}
		if len(req.Password) < 12 {
			http.Error(w, "password must be at least 12 characters", http.StatusBadRequest)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_, err = pool.Exec(r.Context(),
			`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)`,
			req.Username, string(hash), req.Role,
		)
		if err != nil {
			http.Error(w, "username already exists", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// countAdmins is used by both the delete and role-update handlers to refuse
// an action that would leave zero admins.
func countAdmins(r *http.Request, pool *pgxpool.Pool) (int, error) {
	var n int
	err := pool.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE role = 'admin'`).Scan(&n)
	return n, err
}

func deleteUserHandler(store *SessionStore, pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		target, err := GetUser(r.Context(), pool, username)
		if err != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		if target.Role == "admin" {
			n, err := countAdmins(r, pool)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if n <= 1 {
				http.Error(w, "cannot remove the last admin", http.StatusConflict)
				return
			}
		}
		if _, err := pool.Exec(r.Context(), `DELETE FROM users WHERE username = $1`, username); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := store.DeleteByUsername(r.Context(), username); err != nil {
			log.Printf("deleteUserHandler: failed to invalidate sessions for %s: %v", username, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type updateRoleRequest struct {
	Role string `json:"role"`
}

func updateUserRoleHandler(store *SessionStore, pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		var req updateRoleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Role != "admin" && req.Role != "analyst" {
			http.Error(w, "role must be admin or analyst", http.StatusBadRequest)
			return
		}
		target, err := GetUser(r.Context(), pool, username)
		if err != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		if target.Role == "admin" && req.Role == "analyst" {
			n, err := countAdmins(r, pool)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if n <= 1 {
				http.Error(w, "cannot demote the last admin", http.StatusConflict)
				return
			}
		}
		if _, err := pool.Exec(r.Context(), `UPDATE users SET role = $1 WHERE username = $2`, req.Role, username); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := store.DeleteByUsername(r.Context(), username); err != nil {
			log.Printf("updateUserRoleHandler: failed to invalidate sessions for %s: %v", username, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
