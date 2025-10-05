package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Этап 1: Утилиты
func TestHashPasswordAndJWT(t *testing.T) {
	pass := "MyPass123"
	hash, err := hashPassword(pass)
	if err != nil {
		t.Fatal(err)
	}
	if !checkPasswordHash(pass, hash) {
		t.Error("password verification failed")
	}

	token, err := generateToken(1)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := validateToken(token)
	if err != nil || claims.UserID != 1 {
		t.Error("token validation failed")
	}
}

// Этап 2: Бизнес-логика
func TestValidateRegistration(t *testing.T) {
	if msg := validateRegistration("us", "bad@", "123"); msg == "" {
		t.Error("expected validation error, got none")
	}
	if msg := validateRegistration("User1", "user@example.com", "Pass123"); msg != "" {
		t.Errorf("unexpected validation error: %s", msg)
	}
}

// Этап 3: Middleware
func TestAuthMiddleware(t *testing.T) {
	token, _ := generateToken(1)
	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	authMiddleware(meHandler)(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Code)
	}
}

// Этап 4: Контроллеры
func TestRegisterAndLoginFlow(t *testing.T) {
	body := `{"username":"user1","email":"user1@example.com","password":"Pass123"}`
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	registerHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register failed: %d, body: %s", w.Code, w.Body.String())
	}

	loginBody := `{"username":"user1","password":"Pass123"}`
	req = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(loginBody))
	w = httptest.NewRecorder()
	loginHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d, body: %s", w.Code, w.Body.String())
	}

	var resp AuthResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("no token in login response")
	}
}
