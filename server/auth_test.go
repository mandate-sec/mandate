package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthRejectsMalformedCredentialsBeforeStoreAccess(t *testing.T) {
	handler := (&Server{}).requireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler ran")
	}))
	for _, value := range []string{"", "plain-text", "a.b.c.d", "a.b." + strings.Repeat("x", 4096)} {
		request := httptest.NewRequest(http.MethodGet, "/api/session-check", nil)
		request.Header.Set("Authorization", "Bearer "+value)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("expected rejection before database access, got %d", response.Code)
		}
	}
}

func TestAuthRejectsWhenSessionLookupStalls(t *testing.T) {
	store, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetMaxOpenConns(1)
	conn, err := store.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*sessionCheckTimeout)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/session-check", nil)
	token, err := signJWT([]byte("test-only signing key"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	s := &Server{m: &Manager{pg: &db.DB{DB: store}}}
	w := httptest.NewRecorder()
	s.requireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler ran while the session store was unavailable")
	})).ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || ctx.Err() != nil || store.Stats().WaitCount == 0 {
		t.Fatalf("expected bounded pool wait: status=%d request error=%v", w.Code, ctx.Err())
	}
}

func TestSetupStatusTimeoutDoesNotReportUninitialized(t *testing.T) {
	store, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetMaxOpenConns(1)
	conn, err := store.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT)"); err != nil {
		t.Fatal(err)
	}
	// Release the connection eventually even if the handler loses its deadline.
	release := time.AfterFunc(3*sessionCheckTimeout, func() { _ = conn.Close() })
	defer release.Stop()
	s := &Server{m: &Manager{pg: &db.DB{DB: store}}}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/status", nil))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "initialized") || store.Stats().WaitCount == 0 {
		t.Fatalf("unexpected setup status during a stalled query: %d %s", w.Code, w.Body.String())
	}
}

func TestLoginReleasesSlotWhenDatabaseStalls(t *testing.T) {
	store, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetMaxOpenConns(1)
	conn, err := store.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	release := time.AfterFunc(3*sessionCheckTimeout, func() { _ = conn.Close() })
	defer release.Stop()
	s := &Server{m: &Manager{pg: &db.DB{DB: store}}}
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"ARTEX","password":"fixture"}`))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || store.Stats().WaitCount == 0 || !release.Stop() {
		t.Fatalf("expected login to time out before the connection was released, got status %d", w.Code)
	}
	if s.passwordAttempts.active != 0 {
		t.Fatal("timed-out login retained a password-check slot")
	}
}

func TestAdminPasswordComparisonByteLimit(t *testing.T) {
	password := strings.Repeat("界", 24)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !matchesAdminPassword(string(hash), password) || matchesAdminPassword(string(hash), password+"x") {
		t.Fatal("password comparison must use exactly the submitted credential")
	}
}

func signTestSession(s *Server) (string, error) {
	generation, _, err := s.m.pg.GetSetting("auth.session_generation")
	if err != nil {
		return "", err
	}
	return signJWT(sessionSigningKey(s.jwtKey, generation))
}

func TestThrottledLoginReturnsRetryAfterBeforeQuery(t *testing.T) {
	s := &Server{m: &Manager{pg: &db.DB{}}}
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"ARTEX","password":"fixture"}`))
	for range passwordBurst {
		done, _ := s.passwordAttempts.begin(req.RemoteAddr, time.Now())
		if done == nil {
			t.Fatal("failed to seed test budget")
		}
		done()
	}
	req.Header.Set("X-Forwarded-For", "192.0.2.7")
	w := httptest.NewRecorder()
	s.authLogin(w, req)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
}

// GetSetting 对"键不存在"和"读取出错"的返回值只差一个 error：两种情况 value 都是
// 空串。密码相关的 handler 一旦把 error 当成"还没设置密码"，就会在数据库抖动期间
// 敞开初始化入口——authInit 会放行一个未认证请求去覆盖已有的管理员密码，
// authStatus 则会把前端直接送到 /setup 去照着做这件事。
//
// 这两个测试把 handler 的连接池关掉来制造读取失败，断言两处都 fail closed。
func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	// 关掉池子，让后续 GetSetting 返回 error 而不是 sql.ErrNoRows。
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败被当成未初始化会把用户送去 /setup 覆盖密码); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("读失败时不应回答 initialized，得到 %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"password":"correct horse battery"}`)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", body))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败时放行会让未认证请求覆盖已有密码); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("读失败时不应签发 token: %s", w.Body.String())
	}
}

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name, pw string
		wantErr  bool
	}{
		{"空", "", true},
		{"七位", "1234567", true},
		{"八位", "12345678", false},
		{"八个汉字按字符数而非字节数计", "密码密码密码密码", false},
		{"三个汉字够 9 字节但只有 3 个字符", "密码强", true},
		{"72 字节", strings.Repeat("a", 72), false},
		{"73 字节超出 bcrypt 上限", strings.Repeat("a", 73), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.pw); (got != "") != tc.wantErr {
				t.Fatalf("validatePassword(%q)=%q, wantErr=%v", tc.pw, got, tc.wantErr)
			}
		})
	}
}

func TestAuthEndpointsRejectInvalidBodiesBeforeDatabase(t *testing.T) {
	s := new(Server)
	for _, handler := range []http.HandlerFunc{s.authInit, s.authLogin, s.authChangePassword} {
		for _, tc := range []struct {
			body string
			code int
		}{
			{"{}" + strings.Repeat(" ", 8191), 413},
			{"{} {}", 400},
			{" \tnull\n", 400},
			{`{"password":"` + "\xff" + `"}`, 400},
		} {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest("POST", "/", strings.NewReader(tc.body)))
			if w.Code != tc.code {
				t.Fatalf("response %d, want %d", w.Code, tc.code)
			}
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader("{}" + strings.Repeat(" ", 8190)))
	if !readAuthRequest(w, r, &struct{}{}) {
		t.Fatal("valid document exactly at the limit was rejected")
	}
	var credentials struct{ Password string }
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{"password":"密�碼"}`))
	if !readAuthRequest(w, r, &credentials) || credentials.Password != "密�碼" {
		t.Fatal("valid Unicode credential changed during parsing")
	}
}

type authDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *authDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

func TestAuthBodyReadDeadline(t *testing.T) {
	start := time.Now()
	w := &authDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Body = io.NopCloser(iotest.ErrReader(os.ErrDeadlineExceeded))
	if readAuthRequest(w, r, &struct{}{}) || w.Code != http.StatusRequestTimeout {
		t.Fatalf("expired body accepted or wrong status: %d", w.Code)
	}
	if w.deadline.Before(start.Add(10*time.Second)) || w.deadline.After(time.Now().Add(10*time.Second)) {
		t.Fatalf("unexpected read deadline: %v", w.deadline)
	}
}

func TestAuthCredentialFieldsMustBeUnique(t *testing.T) {
	for _, tc := range []struct {
		body string
		ok   bool
	}{
		{`{"password":"first","password":"second"}`, false},
		{`{"password":"first","PASSWORD":"second"}`, false},
		{`{"new_password":"first","new_\u0070assword":"second"}`, false},
		{`{"username":"user","password":"pass","extra":{"password":"nested"}}`, true},
		{`{"password":"pass"}{}`, false},
	} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		var dst struct{ Password string }
		if ok := readAuthRequest(w, r, &dst); ok != tc.ok || (!ok && w.Code != http.StatusBadRequest) {
			t.Fatalf("accepted=%v status=%d for %s", ok, w.Code, tc.body)
		}
	}
}
