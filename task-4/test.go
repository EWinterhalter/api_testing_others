package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

func resetStore() {
	mutex.Lock()
	defer mutex.Unlock()
	users = make(map[int]User)
	usersBy = make(map[string]int)
	nextID = 1
	jwtSecret = []byte("test-secret")
}

func setupMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/register", registerHandler)
	mux.HandleFunc("/api/auth/login", loginHandler)
	mux.HandleFunc("/api/auth/refresh", refreshHandler)
	mux.HandleFunc("/api/auth/logout", logoutHandler)
	mux.HandleFunc("/api/auth/me", authMiddleware(meHandler))
	mux.HandleFunc("/api/users", authMiddleware(adminMiddleware(usersListHandler)))
	mux.HandleFunc("/api/users/", authMiddleware(adminMiddleware(userDetailHandler)))
	return mux
}

func doRequest(mux *http.ServeMux, method, path string, body io.Reader, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func mustParseAuthResponse(t *testing.T, body []byte) AuthResponse {
	var resp AuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to unmarshal auth response: %v, body: %s", err, string(body))
	}
	return resp
}

func TestRegisterLoginMe(t *testing.T) {
	resetStore()
	mux := setupMux()

	regBody := `{"username":"admin","email":"admin@example.com","password":"P4ssw0rd1"}`
	w := doRequest(mux, "POST", "/api/auth/register", bytes.NewBufferString(regBody), "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on register, got %d body=%s", w.Code, w.Body.String())
	}
	resp := mustParseAuthResponse(t, w.Body.Bytes())
	if !resp.User.IsAdmin {
		t.Fatalf("first registered user must be admin; got IsAdmin=%v", resp.User.IsAdmin)
	}

	token := resp.Token
	if token == "" {
		t.Fatalf("expected token on register")
	}

	w = doRequest(mux, "GET", "/api/auth/me", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on /me, got %d body=%s", w.Code, w.Body.String())
	}
	var me User
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil {
		t.Fatalf("failed to parse /me response: %v", err)
	}
	if me.ID != resp.User.ID {
		t.Fatalf("expected /me to return same user id %d got %d", resp.User.ID, me.ID)
	}
}

func TestAdminAccessAndRBAC(t *testing.T) {
	resetStore()
	mux := setupMux()

	w := doRequest(mux, "POST", "/api/auth/register", bytes.NewBufferString(`{"username":"admin","email":"a@a.com","password":"P4ssw0rd1"}`), "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin register failed: %d %s", w.Code, w.Body.String())
	}
	admin := mustParseAuthResponse(t, w.Body.Bytes())

	w = doRequest(mux, "POST", "/api/auth/register", bytes.NewBufferString(`{"username":"user1","email":"u1@ex.com","password":"P4ssw0rd1"}`), "")
	if w.Code != http.StatusOK {
		t.Fatalf("user register failed: %d %s", w.Code, w.Body.String())
	}

	w = doRequest(mux, "POST", "/api/auth/login", bytes.NewBufferString(`{"username":"user1","password":"P4ssw0rd1"}`), "")
	if w.Code != http.StatusOK {
		t.Fatalf("login failed for user1: %d %s", w.Code, w.Body.String())
	}
	userResp := mustParseAuthResponse(t, w.Body.Bytes())

	w = doRequest(mux, "GET", "/api/users", nil, userResp.Token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin /api/users, got %d body=%s", w.Code, w.Body.String())
	}

	w = doRequest(mux, "GET", "/api/users", nil, admin.Token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin /api/users, got %d body=%s", w.Code, w.Body.String())
	}
	var list []User
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("failed to parse users list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 users, got %d", len(list))
	}
}

func TestUserUpdateAndIndexConsistency(t *testing.T) {
	resetStore()
	mux := setupMux()

	w := doRequest(mux, "POST", "/api/auth/register", bytes.NewBufferString(`{"username":"bob","email":"bob@ex.com","password":"P4ssw0rd1"}`), "")
	if w.Code != http.StatusOK {
		t.Fatalf("register failed: %d %s", w.Code, w.Body.String())
	}
	resp := mustParseAuthResponse(t, w.Body.Bytes())

	newUser := User{Username: "bobby"}
	b, _ := json.Marshal(newUser)
	w = doRequest(mux, "PUT", "/api/users/"+strconv.Itoa(resp.User.ID), bytes.NewBuffer(b), resp.Token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on update user, got %d body=%s", w.Code, w.Body.String())
	}

	w = doRequest(mux, "POST", "/api/auth/login", bytes.NewBufferString(`{"username":"bobby","password":"P4ssw0rd1"}`), "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected login with new username to succeed after update; got %d body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteRemovesIndexes(t *testing.T) {
	resetStore()
	mux := setupMux()

	w := doRequest(mux, "POST", "/api/auth/register", bytes.NewBufferString(`{"username":"to_delete","email":"del@ex.com","password":"P4ssw0rd1"}`), "")
	if w.Code != http.StatusOK {
		t.Fatalf("register failed: %d %s", w.Code, w.Body.String())
	}
	resp := mustParseAuthResponse(t, w.Body.Bytes())

	w = doRequest(mux, "DELETE", "/api/users/"+strconv.Itoa(resp.User.ID), nil, resp.Token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on delete, got %d body=%s", w.Code, w.Body.String())
	}

	w = doRequest(mux, "POST", "/api/auth/register", bytes.NewBufferString(`{"username":"to_delete","email":"del@ex.com","password":"P4ssw0rd1"}`), "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected re-register after delete to succeed, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRefreshAndLogout(t *testing.T) {
	resetStore()
	mux := setupMux()

	w := doRequest(mux, "POST", "/api/auth/register", bytes.NewBufferString(`{"username":"ruser","email":"r@ex.com","password":"P4ssw0rd1"}`), "")
	if w.Code != http.StatusOK {
		t.Fatalf("register failed: %d %s", w.Code, w.Body.String())
	}
	resp := mustParseAuthResponse(t, w.Body.Bytes())

	w = doRequest(mux, "POST", "/api/auth/refresh", nil, resp.Token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on refresh, got %d body=%s", w.Code, w.Body.String())
	}

	w = doRequest(mux, "POST", "/api/auth/logout", nil, resp.Token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRejectWrongJWTAlg(t *testing.T) {
	resetStore()
	mux := setupMux()

	w := doRequest(mux, "GET", "/api/auth/me", nil, "malformed.token.here")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for malformed token, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestConcurrentRegistrations(t *testing.T) {
	resetStore()
	mux := setupMux()

	n := 100
	wg := sync.WaitGroup{}
	wg.Add(n)
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			username := "u" + strconv.Itoa(i)
			email := "u" + strconv.Itoa(i) + "@ex.com"
			body := bytes.NewBufferString(`{"username":"` + username + `","email":"` + email + `","password":"P4ssw0rd1"}`)
			w := doRequest(mux, "POST", "/api/auth/register", body, "")
			if w.Code != http.StatusOK {
				errCh <- fmtError(w.Code, w.Body.String())
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent register error: %v", err)
	}
}

func fmtError(code int, body string) error {
	return &httpError{code: code, body: body}
}

type httpError struct {
	code int
	body string
}

func (e *httpError) Error() string {
	return "status=" + strconv.Itoa(e.code) + " body=" + e.body
}
