package platform

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ajcorrea/onegate/internal/passhash"
	"github.com/ajcorrea/onegate/internal/totp"
)

const (
	cookieName      = "og_session"
	pendingTTL      = 10 * time.Minute // entre a senha e o código TOTP
	sessionTTL      = 12 * time.Hour
	idleTimeout     = 2 * time.Hour
	recoveryCount   = 10
	totpIssuer      = "ONE GATE"
	invalidLoginMsg = "E-mail ou senha incorretos."
)

// Session é a sessão autenticada da requisição.
type Session struct {
	TokenHash   string
	UserID      string // id da pessoa
	Email       string // login no painel (usuario@dominio)
	Name        string
	IsAdmin     bool // Admin global
	MFAVerified bool
	TOTPEnabled bool
	Subject     *Subject
}

// can avalia uma função para quem está logado ("" = escopo da plataforma).
func (s *Session) can(fn, customerID string) bool { return s.Subject.Can(fn, customerID).Allowed }

// canSomewhere informa se a função vale na plataforma ou em algum cliente visível.
func (s *Session) canSomewhere(fn string, customerIDs []string) bool {
	if s.can(fn, "") {
		return true
	}
	for _, c := range customerIDs {
		if s.can(fn, c) {
			return true
		}
	}
	return false
}

func (s *Session) actor(r *http.Request) Actor {
	ip, _ := r.Context().Value(ipKey{}).(string)
	global := false
	if s.Subject != nil {
		global = s.Subject.Global()
	}
	return Actor{UserID: s.UserID, Label: s.Email, IsAdmin: s.IsAdmin, Global: global, IP: ip}
}

type sessionKey struct{}
type ipKey struct{}

func sessionFrom(r *http.Request) *Session {
	s, _ := r.Context().Value(sessionKey{}).(*Session)
	return s
}

func newToken() (string, string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	return tok, hashToken(tok)
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func (s *Server) setCookie(w http.ResponseWriter, tok string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: s.SecureCookies,
		SameSite: http.SameSiteStrictMode, MaxAge: int(ttl.Seconds()),
	})
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// loadSession busca a sessão do cookie. Sessões expiradas ou ociosas são apagadas.
func (s *Server) loadSession(r *http.Request) (*Session, error) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	th := hashToken(c.Value)
	now := s.now()
	var sess Session
	var expires, lastSeen time.Time
	var active bool
	err = s.DB.Pool.QueryRow(r.Context(), `
		SELECT s.token_hash, s.person_id::text, a.login, p.name, s.mfa_verified, a.totp_enabled,
		       s.expires_at, s.last_seen_at, a.active AND p.active
		FROM sessions s
		JOIN panel_accounts a ON a.person_id = s.person_id
		JOIN people p ON p.id = s.person_id
		WHERE s.token_hash = $1`, th).
		Scan(&sess.TokenHash, &sess.UserID, &sess.Email, &sess.Name, &sess.MFAVerified, &sess.TOTPEnabled, &expires, &lastSeen, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !active || now.After(expires) || (sess.MFAVerified && now.Sub(lastSeen) > idleTimeout) {
		_, _ = s.DB.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE token_hash = $1`, th)
		return nil, nil
	}
	tx, err := s.DB.Pool.Begin(r.Context())
	if err != nil {
		return nil, err
	}
	sess.Subject, err = loadSubject(r.Context(), tx, sess.UserID)
	_ = tx.Rollback(r.Context())
	if err != nil {
		return nil, err
	}
	sess.IsAdmin = sess.Subject.FullAdmin()
	if now.Sub(lastSeen) > time.Minute {
		_, _ = s.DB.Pool.Exec(r.Context(), `UPDATE sessions SET last_seen_at = $2 WHERE token_hash = $1`, th, now)
	}
	return &sess, nil
}

func (s *Server) withIP(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ipKey{}, s.clientIP(r)))
}

// authed exige sessão completa (senha + TOTP).
func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = s.withIP(r)
		sess, err := s.loadSession(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if sess == nil || !sess.MFAVerified {
			writeError(w, http.StatusUnauthorized, "Faça login para continuar.")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	}
}

// platformFn exige a função no escopo da plataforma.
func (s *Server) platformFn(fn string, h http.HandlerFunc) http.HandlerFunc {
	return s.authed(func(w http.ResponseWriter, r *http.Request) {
		if !sessionFrom(r).can(fn, "") {
			s.serverError(w, r, forbidden(fn))
			return
		}
		h(w, r)
	})
}

// pending exige uma sessão que passou pela senha e ainda aguarda o TOTP.
func (s *Server) pending(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = s.withIP(r)
		sess, err := s.loadSession(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if sess == nil || sess.MFAVerified {
			writeError(w, http.StatusUnauthorized, "Sessão de login expirada. Informe a senha novamente.")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	}
}

type loginRequest struct {
	Login    string `json:"login"` // usuario@dominio
	Password string `json:"password"`
}

type loginResponse struct {
	Next       string `json:"next"` // "totp" | "totp_setup"
	OTPAuthURI string `json:"otpauth_uri,omitempty"`
	Secret     string `json:"secret,omitempty"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r = s.withIP(r)
	var req loginRequest
	if err := decode(r, &req); err != nil {
		s.serverError(w, r, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Login))
	ip := s.clientIP(r)
	key := email + "|" + ip
	if s.limiter.blocked(key, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Muitas tentativas. Aguarde alguns minutos.")
		return
	}

	var userID, hash string
	var active, totpEnabled bool
	var sealed *string
	err := s.DB.Pool.QueryRow(r.Context(), `
		SELECT a.person_id::text, a.password_hash, a.active AND p.active, a.totp_enabled, a.totp_secret
		FROM panel_accounts a JOIN people p ON p.id = a.person_id WHERE lower(a.login) = $1`, email).
		Scan(&userID, &hash, &active, &totpEnabled, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		passhash.VerifyDummy(req.Password)
		s.limiter.fail(key, s.now())
		writeError(w, http.StatusUnauthorized, invalidLoginMsg)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ok, _ := passhash.Verify(req.Password, hash)
	if !ok || !active {
		s.limiter.fail(key, s.now())
		reason := "senha incorreta"
		if ok {
			reason = "usuário desativado"
		}
		_ = s.DB.WithActor(r.Context(), Actor{Label: email, IP: ip}, func(tx pgx.Tx) error {
			return audit(r.Context(), tx, Actor{UserID: userID, Label: email, IP: ip}, nil, "login.falha", "person", userID, map[string]any{"motivo": reason})
		})
		writeError(w, http.StatusUnauthorized, invalidLoginMsg)
		return
	}

	resp := loginResponse{Next: "totp"}
	if !totpEnabled {
		// Primeiro acesso: gera (ou reaproveita) a semente para o cadastro no app autenticador.
		var secret string
		if sealed != nil {
			secret, err = s.Box.Open(*sealed, panelCtx(userID))
		}
		if sealed == nil || err != nil {
			secret, err = totp.NewSecret()
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			enc, err := s.Box.Seal(secret, panelCtx(userID))
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			if _, err := s.DB.Pool.Exec(r.Context(), `UPDATE panel_accounts SET totp_secret = $2, updated_at = now() WHERE person_id = $1`, userID, enc); err != nil {
				s.serverError(w, r, err)
				return
			}
		}
		resp = loginResponse{Next: "totp_setup", Secret: secret, OTPAuthURI: totp.ProvisioningURI(totpIssuer+" (painel)", email, secret)}
	}

	tok, th := newToken()
	if _, err := s.DB.Pool.Exec(r.Context(), `INSERT INTO sessions (token_hash, person_id, mfa_verified, expires_at, ip, user_agent) VALUES ($1, $2, false, $3, $4, $5)`,
		th, userID, s.now().Add(pendingTTL), ip, truncate(r.UserAgent(), 300)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setCookie(w, tok, pendingTTL)
	writeJSON(w, http.StatusOK, resp)
}

type codeRequest struct {
	Code string `json:"code"`
}

// handleTOTP conclui o login (ou o cadastro do TOTP no primeiro acesso).
func (s *Server) handleTOTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var req codeRequest
	if err := decode(r, &req); err != nil {
		s.serverError(w, r, err)
		return
	}
	ip := s.clientIP(r)
	key := "totp|" + sess.UserID
	if s.limiter.blocked(key, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Muitas tentativas. Aguarde alguns minutos.")
		return
	}
	var sealed *string
	if err := s.DB.Pool.QueryRow(r.Context(), `SELECT totp_secret FROM panel_accounts WHERE person_id = $1`, sess.UserID).Scan(&sealed); err != nil {
		s.serverError(w, r, err)
		return
	}
	if sealed == nil {
		writeError(w, http.StatusUnauthorized, "Sessão de login expirada. Informe a senha novamente.")
		return
	}
	secret, err := s.Box.Open(*sealed, panelCtx(sess.UserID))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	step, ok := totp.Validate(secret, strings.ReplaceAll(req.Code, " ", ""), s.now(), totp.DefaultSkew)
	if !ok {
		s.limiter.fail(key, s.now())
		writeError(w, http.StatusUnauthorized, "Código inválido.")
		return
	}
	// Anti-reuso no banco: vale entre várias instâncias da API.
	tag, err := s.DB.Pool.Exec(r.Context(), `UPDATE panel_accounts SET totp_last_step = $2 WHERE person_id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)`, sess.UserID, step)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		s.limiter.fail(key, s.now())
		writeError(w, http.StatusUnauthorized, "Este código já foi usado. Aguarde o próximo.")
		return
	}

	var codes []string
	setup := !sess.TOTPEnabled
	err = s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		if setup {
			if _, err := tx.Exec(r.Context(), `UPDATE panel_accounts SET totp_enabled = true, updated_at = now() WHERE person_id = $1`, sess.UserID); err != nil {
				return err
			}
			c, err := replaceRecoveryCodes(r.Context(), tx, sess.UserID)
			if err != nil {
				return err
			}
			codes = c
			if err := audit(r.Context(), tx, sess.actor(r), nil, "mfa.cadastrado", "person", sess.UserID, nil); err != nil {
				return err
			}
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "login", "person", sess.UserID, map[string]any{"metodo": "totp"})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.limiter.reset(key)
	s.limiter.reset(strings.ToLower(sess.Email) + "|" + ip)
	if err := s.promote(w, r, sess); err != nil {
		s.serverError(w, r, err)
		return
	}
	resp := map[string]any{"ok": true}
	if codes != nil {
		resp["recovery_codes"] = codes
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRecovery conclui o login com um código de recuperação (celular perdido).
func (s *Server) handleRecovery(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if !sess.TOTPEnabled {
		writeError(w, http.StatusBadRequest, "Cadastre o app autenticador primeiro.")
		return
	}
	var req codeRequest
	if err := decode(r, &req); err != nil {
		s.serverError(w, r, err)
		return
	}
	key := "totp|" + sess.UserID
	if s.limiter.blocked(key, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Muitas tentativas. Aguarde alguns minutos.")
		return
	}
	code := normalizeRecovery(req.Code)
	var left int
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE recovery_codes SET used_at = now() WHERE person_id = $1 AND code_hash = $2 AND used_at IS NULL`, sess.UserID, hashToken(code))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return validationError("Código de recuperação inválido ou já usado.")
		}
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM recovery_codes WHERE person_id = $1 AND used_at IS NULL`, sess.UserID).Scan(&left); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "login", "person", sess.UserID, map[string]any{"metodo": "codigo_recuperacao", "restantes": left})
	})
	if err != nil {
		var ve validationError
		if errors.As(err, &ve) {
			s.limiter.fail(key, s.now())
			writeError(w, http.StatusUnauthorized, ve.Error())
			return
		}
		s.serverError(w, r, err)
		return
	}
	if err := s.promote(w, r, sess); err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery_codes_left": left})
}

// promote troca a sessão pendente por uma sessão completa com token novo
// (evita fixação de sessão).
func (s *Server) promote(w http.ResponseWriter, r *http.Request, sess *Session) error {
	tok, th := newToken()
	now := s.now()
	tx, err := s.DB.Pool.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck
	if _, err := tx.Exec(r.Context(), `DELETE FROM sessions WHERE token_hash = $1`, sess.TokenHash); err != nil {
		return err
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO sessions (token_hash, person_id, mfa_verified, expires_at, ip, user_agent) VALUES ($1, $2, true, $3, $4, $5)`,
		th, sess.UserID, now.Add(sessionTTL), s.clientIP(r), truncate(r.UserAgent(), 300)); err != nil {
		return err
	}
	if _, err := tx.Exec(r.Context(), `UPDATE panel_accounts SET last_login_at = $2 WHERE person_id = $1`, sess.UserID, now); err != nil {
		return err
	}
	if err := tx.Commit(r.Context()); err != nil {
		return err
	}
	s.setCookie(w, tok, sessionTTL)
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		_, _ = s.DB.Pool.Exec(r.Context(), `DELETE FROM sessions WHERE token_hash = $1`, hashToken(c.Value))
	}
	s.clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// MeCustomer são as funções da pessoa num cliente.
type MeCustomer struct {
	CustomerID string   `json:"customer_id"`
	Code       string   `json:"code"`
	Name       string   `json:"name"`
	Color      string   `json:"color"`
	Domain     string   `json:"domain"`
	Functions  []string `json:"functions"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	customers := []MeCustomer{}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT id::text, code, name, color, domain FROM customers ORDER BY code`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m MeCustomer
			if err := rows.Scan(&m.CustomerID, &m.Code, &m.Name, &m.Color, &m.Domain); err != nil {
				return err
			}
			m.Functions = sess.Subject.Functions(m.CustomerID)
			if len(m.Functions) > 0 {
				customers = append(customers, m)
			}
		}
		return rows.Err()
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	domain := GlobalDomain
	if i := strings.LastIndex(sess.Email, "@"); i >= 0 {
		domain = sess.Email[i+1:]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": sess.UserID, "login": sess.Email, "name": sess.Name, "domain": domain,
		"is_admin": sess.IsAdmin, "global": sess.Subject.Global(),
		"platform": sess.Subject.Functions(""), "customers": customers,
	})
}

func panelCtx(personID string) string  { return "panel:" + personID }
func deviceCtx(personID string) string { return "device:" + personID }

// replaceRecoveryCodes gera 10 códigos de recuperação novos (os antigos deixam de valer).
func replaceRecoveryCodes(ctx context.Context, tx pgx.Tx, userID string) ([]string, error) {
	if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE person_id = $1`, userID); err != nil {
		return nil, err
	}
	codes := make([]string, recoveryCount)
	for i := range codes {
		b := make([]byte, 10)
		_, _ = rand.Read(b)
		raw := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)) // 16 caracteres, 80 bits
		codes[i] = raw[:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:]
		if _, err := tx.Exec(ctx, `INSERT INTO recovery_codes (person_id, code_hash) VALUES ($1, $2)`, userID, hashToken(raw)); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

func normalizeRecovery(c string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// loginLimiter conta falhas por chave numa janela de tempo.
type loginLimiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	failures map[string][]time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, failures: map[string][]time.Time{}}
}

func (l *loginLimiter) recent(key string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range l.failures[key] {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}
	if keep == nil {
		delete(l.failures, key)
	} else {
		l.failures[key] = keep
	}
	return keep
}

func (l *loginLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key, now)) >= l.max
}

func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[key] = append(l.recent(key, now), now)
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}
