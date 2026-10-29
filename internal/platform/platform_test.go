package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ajcorrea/onegate/internal/secretbox"
	"github.com/ajcorrea/onegate/internal/totp"
)

// Os testes de integração usam um PostgreSQL real:
//
//	ONEGATE_TEST_DATABASE_URL=postgres://onegate:onegate@localhost:5432/onegate_test?sslmode=disable go test ./internal/platform/
//
// O esquema do banco de teste é apagado e recriado.
func testServer(t *testing.T) (*Server, *httptest.Server, *testClock) {
	t.Helper()
	url := os.Getenv("ONEGATE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ONEGATE_TEST_DATABASE_URL não definido")
	}
	ctx := context.Background()
	db, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if _, err := db.Pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil { // idempotente
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, _ := secretbox.New(base64.StdEncoding.EncodeToString(key))
	s := NewServer(db, box, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SecureCookies = false
	clk := &testClock{t: time.Now()}
	s.now = clk.now
	hs := httptest.NewServer(s.Handler())
	t.Cleanup(hs.Close)
	return s, hs, clk
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

type client struct {
	t  *testing.T
	hs *httptest.Server
	c  *http.Client
}

func newClient(t *testing.T, hs *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, hs: hs, c: &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.hs.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			c.t.Fatalf("%s %s: resposta não é JSON: %s", method, path, b)
		}
	}
	return resp.StatusCode
}

// login faz senha + TOTP (com cadastro no primeiro acesso) e devolve os códigos de recuperação, se gerados.
func (c *client) login(clk *testClock, email, password string, secret *string) []string {
	c.t.Helper()
	var lr loginResponse
	if st := c.do("POST", "/api/auth/login", map[string]string{"email": email, "password": password}, &lr); st != 200 {
		c.t.Fatalf("login %s: status %d", email, st)
	}
	if lr.Next == "totp_setup" {
		*secret = lr.Secret
	}
	clk.add(30 * time.Second) // passo novo: não colide com o anti-reuso
	code, _ := totp.Code(*secret, clk.now())
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if st := c.do("POST", "/api/auth/totp", map[string]string{"code": code}, &out); st != 200 {
		c.t.Fatalf("totp %s: status %d", email, st)
	}
	return out.RecoveryCodes
}

func TestPlatformFlow(t *testing.T) {
	s, hs, clk := testServer(t)
	ctx := context.Background()
	const adminPW, techPW = "senha-do-admin-123", "senha-do-tecnico-1"

	if _, err := s.CreatePanelUser(ctx, System, NewPanelUser{Email: "Admin@OnTelecom.io", Name: "Admin", Password: adminPW, IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	admin := newClient(t, hs)

	// Senha errada e acesso sem login
	if st := admin.do("POST", "/api/auth/login", map[string]string{"email": "admin@ontelecom.io", "password": "errada-errada"}, nil); st != 401 {
		t.Fatalf("senha errada: %d", st)
	}
	if st := admin.do("GET", "/api/customers", nil, nil); st != 401 {
		t.Fatalf("sem login: %d", st)
	}

	// Primeiro login: cadastro do TOTP e códigos de recuperação
	var adminSecret string
	codes := admin.login(clk, "admin@ontelecom.io", adminPW, &adminSecret)
	if len(codes) != 10 || adminSecret == "" {
		t.Fatalf("cadastro do TOTP: secret=%q codes=%v", adminSecret, codes)
	}
	var me map[string]any
	if st := admin.do("GET", "/api/auth/me", nil, &me); st != 200 || me["is_admin"] != true || me["email"] != "admin@ontelecom.io" {
		t.Fatalf("me: %d %v", st, me)
	}

	// CSRF: alteração sem JSON é recusada
	req, _ := http.NewRequest("POST", hs.URL+"/api/customers", bytes.NewBufferString("code=XYZ"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, _ := admin.c.Do(req); resp.StatusCode != 415 {
		t.Fatalf("CSRF: %d", resp.StatusCode)
	}

	// Clientes
	var nsf, vlc Customer
	if st := admin.do("POST", "/api/customers", map[string]any{"code": "nsf", "name": "NetSul Fibra", "color": "#2563eb"}, &nsf); st != 201 || nsf.Code != "NSF" || nsf.Color != "#2563EB" {
		t.Fatalf("criar NSF: %d %+v", st, nsf)
	}
	if st := admin.do("POST", "/api/customers", map[string]any{"code": "VLC", "name": "Serra Logística", "segment": "logistica", "color": "#B45309", "mfa": "off"}, &vlc); st != 201 {
		t.Fatalf("criar VLC: %d", st)
	}
	if st := admin.do("POST", "/api/customers", map[string]any{"code": "NSF", "name": "Outro", "color": "#000000"}, nil); st != 409 {
		t.Fatalf("código duplicado: %d", st)
	}
	if st := admin.do("POST", "/api/customers", map[string]any{"code": "NS", "name": "X", "color": "#000000"}, nil); st != 400 {
		t.Fatalf("código inválido: %d", st)
	}
	var upd Customer
	if st := admin.do("PATCH", "/api/customers/"+vlc.ID, map[string]any{"trust_window_seconds": 1800}, &upd); st != 200 || upd.TrustWindowSeconds != 1800 {
		t.Fatalf("alterar cliente: %d %+v", st, upd)
	}

	// Pessoa com acesso ao painel: Servidores (escrita) e Auditoria (leitura) só na NSF
	var tech Person
	if st := admin.do("POST", "/api/people", map[string]any{"name": "Técnico", "email": "tecnico@ontelecom.io"}, &tech); st != 201 || tech.Panel != nil || tech.Device != nil {
		t.Fatalf("criar pessoa: %d %+v", st, tech)
	}
	if st := admin.do("PUT", "/api/people/"+tech.ID+"/panel", map[string]any{"login_email": "tecnico@ontelecom.io"}, nil); st != 400 {
		t.Fatalf("acesso ao painel sem senha inicial: %d", st)
	}
	if st := admin.do("PUT", "/api/people/"+tech.ID+"/panel", map[string]any{"login_email": "tecnico@ontelecom.io", "password": "curta"}, nil); st != 400 {
		t.Fatalf("senha curta: %d", st)
	}
	if st := admin.do("PUT", "/api/people/"+tech.ID+"/panel", map[string]any{"login_email": "tecnico@ontelecom.io", "password": techPW}, &tech); st != 200 || tech.Panel == nil || !tech.Panel.Active {
		t.Fatalf("acesso ao painel: %d %+v", st, tech.Panel)
	}
	perms := []Permission{{CustomerID: nsf.ID, Module: "servers", Level: "write"}, {CustomerID: nsf.ID, Module: "audit", Level: "read"}}
	if st := admin.do("PUT", "/api/people/"+tech.ID+"/panel/permissions", perms, &tech); st != 200 || len(tech.Panel.Permissions) != 2 {
		t.Fatalf("permissões: %d %+v", st, tech.Panel)
	}
	if st := admin.do("PUT", "/api/people/"+tech.ID+"/panel/permissions", []Permission{{CustomerID: nsf.ID, Module: "financeiro", Level: "read"}}, nil); st != 400 {
		t.Fatalf("módulo inválido: %d", st)
	}

	techC := newClient(t, hs)
	var techSecret string
	techC.login(clk, "tecnico@ontelecom.io", techPW, &techSecret)
	var techMe struct {
		Customers []MeCustomer `json:"customers"`
	}
	if st := techC.do("GET", "/api/auth/me", nil, &techMe); st != 200 || len(techMe.Customers) != 1 || techMe.Customers[0].Modules["servers"] != "write" {
		t.Fatalf("permissões no /me: %d %+v", st, techMe)
	}

	// RLS: o técnico só enxerga a NSF
	var list []Customer
	if st := techC.do("GET", "/api/customers", nil, &list); st != 200 || len(list) != 1 || list[0].Code != "NSF" {
		t.Fatalf("isolamento por cliente: %d %+v", st, list)
	}
	if st := techC.do("GET", "/api/customers/"+vlc.ID, nil, nil); st != 404 {
		t.Fatalf("técnico não pode ver VLC: %d", st)
	}
	if st := techC.do("POST", "/api/customers", map[string]any{"code": "ABC", "name": "Abc", "color": "#000000"}, nil); st != 403 {
		t.Fatalf("técnico não pode criar cliente: %d", st)
	}
	if st := techC.do("GET", "/api/people", nil, nil); st != 403 {
		t.Fatalf("técnico não pode listar pessoas: %d", st)
	}

	// Pessoa só com acesso aos equipamentos (sem painel): credencial separada
	var field Person
	admin.do("POST", "/api/people", map[string]any{"name": "Terceiro Redes"}, &field)
	if st := admin.do("PUT", "/api/people/"+field.ID+"/device", map[string]any{"username": "terceiro.redes", "password": "senha-equipamento-1"}, &field); st != 200 || field.Device == nil || field.Panel != nil {
		t.Fatalf("acesso aos equipamentos: %d %+v", st, field)
	}
	if st := admin.do("PUT", "/api/people/"+tech.ID+"/device", map[string]any{"username": "terceiro.redes", "password": "outra-senha-123"}, nil); st != 409 {
		t.Fatalf("usuário de equipamento duplicado: %d", st)
	}
	var otp struct {
		Secret string `json:"secret"`
		URI    string `json:"otpauth_uri"`
	}
	if st := admin.do("POST", "/api/people/"+field.ID+"/device/totp", map[string]any{}, &otp); st != 200 || otp.Secret == "" || !bytes.Contains([]byte(otp.URI), []byte("terceiro.redes")) {
		t.Fatalf("TOTP de equipamento: %d %+v", st, otp)
	}
	if st := admin.do("PUT", "/api/people/"+field.ID+"/device/customers", []string{nsf.ID}, &field); st != 200 || len(field.Device.Customers) != 1 || !field.Device.TOTPConfigured {
		t.Fatalf("clientes do equipamento: %d %+v", st, field.Device)
	}
	// O segredo do equipamento é cifrado com contexto próprio: não é o TOTP do painel
	var sealed string
	_ = s.DB.Pool.QueryRow(ctx, `SELECT totp_secret FROM device_accounts WHERE person_id = $1`, field.ID).Scan(&sealed)
	if got, err := s.Box.Open(sealed, deviceCtx(field.ID)); err != nil || got != otp.Secret {
		t.Fatalf("segredo do equipamento: %v", err)
	}
	if _, err := s.Box.Open(sealed, panelCtx(field.ID)); err == nil {
		t.Fatal("segredo do equipamento não pode abrir no contexto do painel")
	}
	// Quem só tem acesso aos equipamentos não entra no painel
	fc := newClient(t, hs)
	if st := fc.do("POST", "/api/auth/login", map[string]string{"email": "terceiro.redes", "password": "senha-equipamento-1"}, nil); st != 401 {
		t.Fatalf("credencial de equipamento entrou no painel: %d", st)
	}

	// Auditoria: o técnico vê só eventos da NSF; o admin vê tudo
	var techAudit, adminAudit []AuditEntry
	techC.do("GET", "/api/audit", nil, &techAudit)
	admin.do("GET", "/api/audit", nil, &adminAudit)
	for _, e := range techAudit {
		if e.CustomerCode == nil || *e.CustomerCode != "NSF" {
			t.Fatalf("técnico viu evento fora da NSF: %+v", e)
		}
	}
	if len(techAudit) == 0 || len(adminAudit) <= len(techAudit) {
		t.Fatalf("auditoria: técnico=%d admin=%d", len(techAudit), len(adminAudit))
	}

	// Auditoria é somente acréscimo: nem o administrador altera ou apaga eventos
	_ = s.DB.WithActor(ctx, System, func(tx pgx.Tx) error {
		_, _ = tx.Exec(ctx, `UPDATE audit_log SET action = 'x'`)
		_, _ = tx.Exec(ctx, `DELETE FROM audit_log`)
		return nil
	})
	var changed, total int
	_ = s.DB.WithActor(ctx, System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action = 'x'), count(*) FROM audit_log`).Scan(&changed, &total)
	})
	if changed != 0 || total == 0 {
		t.Fatalf("audit_log foi alterado: alterados=%d total=%d", changed, total)
	}

	// Reuso do mesmo código TOTP é recusado
	other := newClient(t, hs)
	other.do("POST", "/api/auth/login", map[string]string{"email": "tecnico@ontelecom.io", "password": techPW}, nil)
	code, _ := totp.Code(techSecret, clk.now())
	if st := other.do("POST", "/api/auth/totp", map[string]string{"code": code}, nil); st != 401 {
		t.Fatalf("reuso do código TOTP: %d", st)
	}

	// Código de recuperação: funciona uma vez
	rc := newClient(t, hs)
	rc.do("POST", "/api/auth/login", map[string]string{"email": "admin@ontelecom.io", "password": adminPW}, nil)
	if st := rc.do("POST", "/api/auth/recovery", map[string]string{"code": codes[0]}, nil); st != 200 {
		t.Fatalf("código de recuperação: %d", st)
	}
	rc2 := newClient(t, hs)
	rc2.do("POST", "/api/auth/login", map[string]string{"email": "admin@ontelecom.io", "password": adminPW}, nil)
	if st := rc2.do("POST", "/api/auth/recovery", map[string]string{"code": codes[0]}, nil); st != 401 {
		t.Fatalf("código de recuperação reutilizado: %d", st)
	}

	// Desativar a pessoa derruba as sessões dela
	if st := admin.do("PATCH", "/api/people/"+tech.ID, map[string]any{"active": false}, nil); st != 200 {
		t.Fatalf("desativar: %d", st)
	}
	if st := techC.do("GET", "/api/customers", nil, nil); st != 401 {
		t.Fatalf("sessão de pessoa desativada continua válida: %d", st)
	}

	// Logout
	if st := admin.do("POST", "/api/auth/logout", map[string]any{}, nil); st != 200 {
		t.Fatalf("logout: %d", st)
	}
	if st := admin.do("GET", "/api/auth/me", nil, nil); st != 401 {
		t.Fatalf("depois do logout: %d", st)
	}
}

func TestLoginRateLimit(t *testing.T) {
	s, hs, _ := testServer(t)
	if _, err := s.CreatePanelUser(context.Background(), System, NewPanelUser{Email: "a@b.io", Name: "Ana", Password: "senha-correta-123"}); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, hs)
	for i := 0; i < 5; i++ {
		c.do("POST", "/api/auth/login", map[string]string{"email": "a@b.io", "password": "errada-errada"}, nil)
	}
	if st := c.do("POST", "/api/auth/login", map[string]string{"email": "a@b.io", "password": "senha-correta-123"}, nil); st != 429 {
		t.Fatalf("deveria bloquear depois de 5 falhas: %d", st)
	}
}
