package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	authPassKey = "auth.password_hash"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

func (s *Server) beginPasswordCheck(w http.ResponseWriter, r *http.Request) (func(), bool) {
	done, retry := s.passwordAttempts.begin(r.RemoteAddr, time.Now())
	if done == nil {
		w.Header().Set("Retry-After", strconv.Itoa(int((retry+time.Second-1)/time.Second)))
		writeErr(w, http.StatusTooManyRequests, "Too many password attempts. Try again later.")
		return nil, false
	}
	return done, true
}

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// requireAuth wraps h with JWT validation.
// Only initial setup, sign-in, status and health are public.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		w.Header().Set("Cache-Control", "no-store")
		switch p {
		case "/api/auth/status", "/api/auth/init", "/api/auth/login", "/api/health":
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErr(w, 401, "未授权")
			return
		}
		pg := s.pg(w)
		if pg == nil {
			return
		}
		checkCtx, stop := context.WithTimeout(r.Context(), sessionCheckTimeout)
		generation, _, err := pg.GetSettingContext(checkCtx, "auth.session_generation")
		stop()
		if err != nil {
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		expires, valid := sessionExpiry(tok, sessionSigningKey(s.jwtKey, generation))
		if !valid {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		session := streamSession{expires: expires, current: func(ctx context.Context) bool {
			current, _, err := pg.GetSettingContext(ctx, "auth.session_generation")
			return err == nil && current == generation
		}}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), streamSessionKey{}, session)))
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// Read the entire bounded document so trailing values and over-limit padding
// cannot be hidden behind a valid first JSON value.
func readAuthRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	const limit = 8192
	// ReadHeaderTimeout ends before the body. Limit only the authentication
	// request here so uploads and long-lived response streams keep their policy.
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeErr(w, http.StatusServiceUnavailable, "请求暂时不可用")
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		writeErr(w, http.StatusRequestTimeout, "请求超时")
		return false
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, "请求体过大")
		return false
	}
	// The JSON decoder accepts null for a struct and silently replaces invalid
	// UTF-8 in strings. Both are inappropriate for credential documents.
	if err != nil || !utf8.Valid(body) || bytes.Equal(bytes.TrimSpace(body), []byte("null")) || json.Unmarshal(body, dst) != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return false
	}
	return true
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password   string `json:"password"`
		SetupToken string `json:"setupToken"`
	}
	if !readAuthRequest(w, r, &req) {
		return
	}

	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, generation, err := pg.AdminCredentials()
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "密码已设置")
		return
	}

	if req.Password == "" {
		writeErr(w, 400, "密码不能为空")
		return
	}
	if !validSetupToken(req.SetupToken, os.Getenv("MANDATE_SETUP_TOKEN_SHA256")) {
		writeErr(w, http.StatusForbidden, "Setup requires the installation owner's setup token.")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !inserted {
		writeErr(w, 403, "密码已设置")
		return
	}
	tok, err := signJWT(sessionSigningKey(s.jwtKey, generation))
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password requires a current session and the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !readAuthRequest(w, r, &req) {
		return
	}

	pg := s.pg(w)
	if pg == nil {
		return
	}

	if req.NewPassword == "" {
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	done, allowed := s.beginPasswordCheck(w, r)
	if !allowed {
		return
	}
	defer done()
	hash, generation, err := pg.AdminCredentials()
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !verifyJWT(extractToken(r), sessionSigningKey(s.jwtKey, generation)) {
		writeErr(w, 401, "未授权")
		return
	}
	if hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if !matchesAdminPassword(hash, req.OldPassword) {
		writeErr(w, 401, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	changed, err := pg.ChangeAdminPassword(hash, string(newHash), rand.Text())
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !changed {
		writeErr(w, 409, "Password changed concurrently. Sign in again.")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readAuthRequest(w, r, &req) {
		return
	}

	pg := s.pg(w)
	if pg == nil {
		return
	}

	if req.Username != "ARTEX" {
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	done, allowed := s.beginPasswordCheck(w, r)
	if !allowed {
		return
	}
	defer done()
	hash, generation, err := pg.AdminCredentials()
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if !matchesAdminPassword(hash, req.Password) {
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	tok, err := signJWT(sessionSigningKey(s.jwtKey, generation))
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

func matchesAdminPassword(hash, password string) bool {
	return len(password) <= maxPasswordBytes && bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
