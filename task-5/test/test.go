package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterLoginFlow(t *testing.T) {
	// 1 уровень
	registerPayload := `{"username":"testuser","email":"test@example.com","password":"Pass123"}`
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBufferString(registerPayload))
	w := httptest.NewRecorder()
	registerHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body: %s", w.Code, w.Body.String())
	}

	var regResp AuthResponse
	json.NewDecoder(w.Body).Decode(&regResp)
	if regResp.User.Username != "testuser" {
		t.Error("wrong username in response")
	}

	// 2 уровень
	loginPayload := `{"username":"testuser","password":"Pass123"}`
	req = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(loginPayload))
	w = httptest.NewRecorder()
	loginHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d", w.Code)
	}
}

func TestAuthMiddleware(t *testing.T) {
	token, _ := generateToken(1)

	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	authMiddleware(meHandler)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
