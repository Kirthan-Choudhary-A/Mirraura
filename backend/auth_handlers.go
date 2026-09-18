package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type ctxKey int

const sessionCtxKey ctxKey = 0

const sessionCookieName = "mirraura_session"

// dummyPasswordHash lets loginHandler run exactly one bcrypt comparison
// whether or not the username exists, so an unknown username takes the
// same time as a wrong password for a real one — without this, Go's ||
// short-circuit makes an unknown-username response measurably faster
// than a wrong-password response, which leaks which usernames exist.
var dummyPasswordHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("dummy-password-for-constant-time-login"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return h
}()

func sessionFromContext(ctx context.Context) (Session, bool) {
	sess, ok := ctx.Value(sessionCtxKey).(Session)
	return sess, ok
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func requireAuth(store *SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			sess, ok := store.Get(cookie.Value)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), sessionCtxKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := sessionFromContext(r.Context())
			if !ok || sess.Role != role {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func loginHandler(store *SessionStore, users map[string]User, limiter *LoginLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ip := clientIP(r)
		if !limiter.Allow(ip) {
			http.Error(w, "too many failed login attempts, try again later", http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		user, ok := users[req.Username]
		hash := dummyPasswordHash
		if ok {
			hash = []byte(user.PasswordHash)
		}
		match := bcrypt.CompareHashAndPassword(hash, []byte(req.Password)) == nil
		if !ok || !match {
			limiter.RecordFailure(ip)
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		token := store.Create(user.Username, user.Role)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"username": user.Username, "role": user.Role})
	}
}

func logoutHandler(store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			store.Delete(cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			MaxAge:   -1,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

func meHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := sessionFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"username": sess.Username, "role": sess.Role})
	}
}
