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
	"strings"
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
	if err := db.EnsureBuiltins(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureBuiltins(ctx); err != nil { // idempotente
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
	if st := c.do("POST", "/api/auth/login", map[string]string{"login": email, "password": password}, &lr); st != 200 {
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
	const adminPW, opPW, juliaPW, pedroPW = "senha-do-admin-123", "senha-do-operador-1", "senha-da-julia-123", "senha-do-pedro-123"

	if _, err := s.CreatePanelUser(ctx, System, NewPanelUser{Login: "admin", Name: "Admin", Password: adminPW, TypeKey: "global_admin"}); err != nil {
		t.Fatal(err)
	}
	admin := newClient(t, hs)
	if st := admin.do("POST", "/api/auth/login", map[string]string{"login": "admin@onegate.systems", "password": "errada-errada"}, nil); st != 401 {
		t.Fatalf("senha errada: %d", st)
	}
	if st := admin.do("GET", "/api/customers", nil, nil); st != 401 {
		t.Fatalf("sem login: %d", st)
	}
	var adminSecret string
	codes := admin.login(clk, "admin@onegate.systems", adminPW, &adminSecret)
	if len(codes) != 10 {
		t.Fatalf("códigos de recuperação: %v", codes)
	}
	var me map[string]any
	if st := admin.do("GET", "/api/auth/me", nil, &me); st != 200 || me["is_admin"] != true || me["login"] != "admin@onegate.systems" || me["domain"] != "onegate.systems" {
		t.Fatalf("me: %d %v", st, me)
	}

	// CSRF
	req, _ := http.NewRequest("POST", hs.URL+"/api/customers", bytes.NewBufferString("code=XYZ"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, _ := admin.c.Do(req); resp.StatusCode != 415 {
		t.Fatalf("CSRF: %d", resp.StatusCode)
	}

	// Clientes com domínio
	var nsf, slg Customer
	if st := admin.do("POST", "/api/customers", map[string]any{"code": "nsf", "name": "NetSul Fibra", "domain": "@NetSulFibra.com.br", "color": "#2563eb"}, &nsf); st != 201 || nsf.Domain != "netsulfibra.com.br" {
		t.Fatalf("criar NSF: %d %+v", st, nsf)
	}
	if st := admin.do("POST", "/api/customers", map[string]any{"code": "SLG", "name": "Serra Logística", "domain": "serralogistica.com.br", "segment": "logistica", "color": "#6D28D9"}, &slg); st != 201 {
		t.Fatalf("criar SLG: %d", st)
	}
	for _, bad := range []map[string]any{
		{"code": "ABC", "name": "Abc", "domain": "onegate.systems", "color": "#000000"},    // reservado
		{"code": "ABD", "name": "Abd", "domain": "sem-ponto", "color": "#000000"},          // inválido
		{"code": "ABE", "name": "Abe", "domain": "netsulfibra.com.br", "color": "#000000"}, // duplicado
		{"code": "ABF", "name": "Abf", "color": "#000000"},                                 // sem domínio
	} {
		if st := admin.do("POST", "/api/customers", bad, nil); st != 400 && st != 409 {
			t.Fatalf("cliente inválido aceito (%v): %d", bad, st)
		}
	}
	if st := admin.do("PATCH", "/api/customers/"+nsf.ID, map[string]any{"domain": "outro.com.br"}, nil); st != 400 {
		t.Fatalf("troca de domínio: %d", st)
	}

	// Tipos prontos
	var types []AccessType
	admin.do("GET", "/api/access-types", nil, &types)
	tid := map[string]string{}
	for _, ty := range types {
		if ty.Key != nil {
			tid[*ty.Key] = ty.ID
		}
	}
	if len(tid) != 4 {
		t.Fatalf("tipos prontos: %+v", types)
	}

	// Operador global (domínio onegate.systems)
	var marcos Person
	admin.do("POST", "/api/people", map[string]any{"name": "Marcos Ribeiro", "email": "marcos@ontelecom.io"}, &marcos)
	if st := admin.do("PUT", "/api/people/"+marcos.ID+"/panel", map[string]any{"login": "marcos", "password": opPW, "access_type_id": tid["global_operator"]}, &marcos); st != 200 || marcos.Panel.Login != "marcos@onegate.systems" {
		t.Fatalf("operador global: %d %+v", st, marcos.Panel)
	}

	// Admin do cliente (domínio netsulfibra.com.br)
	var julia Person
	if st := admin.do("POST", "/api/people", map[string]any{"name": "Júlia Santos", "customer_id": nsf.ID}, &julia); st != 201 || julia.Domain != "netsulfibra.com.br" {
		t.Fatalf("pessoa do cliente: %d %+v", st, julia)
	}
	if st := admin.do("PUT", "/api/people/"+julia.ID+"/panel", map[string]any{"login": "julia", "password": juliaPW, "access_type_id": tid["global_operator"]}, nil); st != 400 {
		t.Fatalf("pessoa de cliente com tipo global: %d", st)
	}
	if st := admin.do("PUT", "/api/people/"+julia.ID+"/panel", map[string]any{"login": "julia@valeconecta.com.br", "password": juliaPW, "access_type_id": tid["customer_admin"]}, nil); st != 400 {
		t.Fatalf("login com domínio errado: %d", st)
	}
	if st := admin.do("PUT", "/api/people/"+julia.ID+"/panel", map[string]any{"login": "julia", "password": juliaPW, "access_type_id": tid["customer_admin"]}, &julia); st != 200 || julia.Panel.Login != "julia@netsulfibra.com.br" {
		t.Fatalf("admin do cliente: %d %+v", st, julia.Panel)
	}

	// Operador global: vê todos os clientes, altera parâmetros, não cadastra cliente nem gerencia pessoas
	op := newClient(t, hs)
	var opSecret string
	op.login(clk, "marcos@onegate.systems", opPW, &opSecret)
	opLoginAt := clk.now()
	// Anti-reuso: o mesmo código, no mesmo passo, não serve para outra sessão
	replay := newClient(t, hs)
	replay.do("POST", "/api/auth/login", map[string]string{"login": "marcos@onegate.systems", "password": opPW}, nil)
	sameCode, _ := totp.Code(opSecret, clk.now())
	var rerr map[string]string
	if st := replay.do("POST", "/api/auth/totp", map[string]string{"code": sameCode}, &rerr); st != 401 || !strings.Contains(rerr["error"], "já foi usado") {
		t.Fatalf("reuso imediato do código: %d %v", st, rerr)
	}
	var opMe struct {
		Global    bool         `json:"global"`
		Platform  []string     `json:"platform"`
		Customers []MeCustomer `json:"customers"`
	}
	op.do("GET", "/api/auth/me", nil, &opMe)
	if !opMe.Global || len(opMe.Customers) != 2 || !contains(opMe.Platform, "admin.params") || contains(opMe.Platform, "admin.customers.edit") {
		t.Fatalf("operador global /me: %+v", opMe)
	}
	if st := op.do("POST", "/api/customers", map[string]any{"code": "XXX", "name": "X", "domain": "x.com.br", "color": "#000000"}, nil); st != 403 {
		t.Fatalf("operador cadastrou cliente: %d", st)
	}
	if st := op.do("POST", "/api/people", map[string]any{"name": "Fulano"}, nil); st != 403 {
		t.Fatalf("operador cadastrou pessoa: %d", st)
	}

	// Admin do cliente: só a NSF
	jc := newClient(t, hs)
	var jSecret string
	jc.login(clk, "julia@netsulfibra.com.br", juliaPW, &jSecret)
	var list []Customer
	if st := jc.do("GET", "/api/customers", nil, &list); st != 200 || len(list) != 1 || list[0].Code != "NSF" {
		t.Fatalf("isolamento: %d %+v", st, list)
	}
	if st := jc.do("GET", "/api/customers/"+slg.ID, nil, nil); st != 404 {
		t.Fatalf("admin do cliente viu outro cliente: %d", st)
	}
	if st := jc.do("POST", "/api/people", map[string]any{"name": "Global Indevido"}, nil); st != 403 {
		t.Fatalf("admin do cliente criou pessoa global: %d", st)
	}
	if st := jc.do("POST", "/api/people", map[string]any{"name": "Fora", "customer_id": slg.ID}, nil); st != 403 {
		t.Fatalf("admin do cliente criou pessoa em outro cliente: %d", st)
	}
	var pedro Person
	if st := jc.do("POST", "/api/people", map[string]any{"name": "Pedro Lima", "customer_id": nsf.ID}, &pedro); st != 201 {
		t.Fatalf("admin do cliente criou pessoa: %d", st)
	}
	var grp struct {
		ID string `json:"id"`
	}
	if st := jc.do("POST", "/api/panel-groups", map[string]any{"name": "Suporte N1", "customer_id": nsf.ID, "base_type_id": tid["global_operator"]}, nil); st != 400 {
		t.Fatalf("grupo de cliente com tipo global: %d", st)
	}
	if st := jc.do("POST", "/api/panel-groups", map[string]any{"name": "Suporte N1", "customer_id": nsf.ID, "base_type_id": tid["customer_operator"]}, &grp); st != 201 {
		t.Fatalf("criar grupo: %d", st)
	}
	if st := jc.do("PUT", "/api/panel-groups/"+grp.ID+"/overrides", map[string]string{"commands.run": "deny"}, nil); st != 200 {
		t.Fatalf("exceção do grupo: %d", st)
	}
	if st := jc.do("PUT", "/api/people/"+pedro.ID+"/panel", map[string]any{"login": "pedro.lima", "password": pedroPW, "group_ids": []string{grp.ID}}, &pedro); st != 200 {
		t.Fatalf("acesso do pedro: %d", st)
	}
	if st := jc.do("PUT", "/api/people/"+pedro.ID+"/panel", map[string]any{"login": "pedro.lima", "access_type_id": tid["global_admin"]}, nil); st != 400 && st != 403 {
		t.Fatalf("escalada para Admin global: %d", st)
	}
	if st := jc.do("PUT", "/api/people/"+julia.ID+"/panel", map[string]any{"login": "julia", "access_type_id": tid["customer_operator"]}, nil); st != 400 {
		t.Fatalf("alterou as próprias permissões: %d", st)
	}
	var d Decision
	jc.do("POST", "/api/permissions/simulate", map[string]string{"person_id": pedro.ID, "customer_id": nsf.ID, "function": "commands.run"}, &d)
	if d.Allowed || d.Reason != "Negado pelo grupo Suporte N1" {
		t.Fatalf("simulação (grupo nega): %+v", d)
	}
	jc.do("POST", "/api/permissions/simulate", map[string]string{"person_id": pedro.ID, "customer_id": slg.ID, "function": "servers.view"}, &d)
	if d.Allowed {
		t.Fatalf("pedro alcançou outro cliente: %+v", d)
	}
	if st := jc.do("PUT", "/api/people/"+pedro.ID+"/panel/overrides", map[string]string{"servers.updates": "allow", "commands.run": "allow"}, nil); st != 200 {
		t.Fatalf("exceções do usuário: %d", st)
	}
	jc.do("POST", "/api/permissions/simulate", map[string]string{"person_id": pedro.ID, "customer_id": nsf.ID, "function": "commands.run"}, &d)
	if !d.Allowed || d.Reason != "Permitir neste usuário" {
		t.Fatalf("exceção do usuário vence o grupo: %+v", d)
	}
	if st := jc.do("PUT", "/api/people/"+pedro.ID+"/panel/overrides", map[string]string{"admin.params": "allow"}, nil); st != 403 {
		t.Fatalf("concedeu função que não tem: %d", st)
	}
	if st := jc.do("POST", "/api/access-types", map[string]any{"name": "Meu tipo", "scope": "customer"}, nil); st != 403 {
		t.Fatalf("admin do cliente criou tipo: %d", st)
	}

	// Credencial de equipamento com domínio
	if st := jc.do("PUT", "/api/people/"+pedro.ID+"/device", map[string]any{"username": "pedro.lima@valeconecta.com.br", "password": "senha-equipamento-1"}, nil); st != 400 {
		t.Fatalf("usuário AAA com domínio errado: %d", st)
	}
	if st := jc.do("PUT", "/api/people/"+pedro.ID+"/device", map[string]any{"username": "pedro.lima", "password": "senha-equipamento-1"}, &pedro); st != 200 || pedro.Device.Username != "pedro.lima@netsulfibra.com.br" {
		t.Fatalf("usuário AAA: %d %+v", st, pedro.Device)
	}
	var otp struct {
		Secret string `json:"secret"`
	}
	if st := jc.do("POST", "/api/people/"+pedro.ID+"/device/totp", map[string]any{}, &otp); st != 200 || otp.Secret == "" {
		t.Fatalf("TOTP de equipamento: %d", st)
	}
	var sealed string
	_ = s.DB.Pool.QueryRow(ctx, `SELECT totp_secret FROM device_accounts WHERE person_id = $1`, pedro.ID).Scan(&sealed)
	if _, err := s.Box.Open(sealed, panelCtx(pedro.ID)); err == nil {
		t.Fatal("segredo do equipamento não pode abrir no contexto do painel")
	}
	fc := newClient(t, hs)
	if st := fc.do("POST", "/api/auth/login", map[string]string{"login": "pedro.lima@netsulfibra.com.br", "password": "senha-equipamento-1"}, nil); st != 401 {
		t.Fatalf("credencial de equipamento entrou no painel: %d", st)
	}

	// Pessoas visíveis: Júlia só vê pessoas da NSF; operador global vê todas (tem "Pessoas: ver")
	var jp, op2 []Person
	jc.do("GET", "/api/people", nil, &jp)
	for _, p := range jp {
		if p.CustomerID == nil || *p.CustomerID != nsf.ID {
			t.Fatalf("admin do cliente viu pessoa de fora: %+v", p)
		}
	}
	op.do("GET", "/api/people", nil, &op2)
	if len(op2) != 4 {
		t.Fatalf("operador global deveria ver 4 pessoas, viu %d", len(op2))
	}

	// Auditoria por função e cliente
	var jAudit, opAudit, adminAudit []AuditEntry
	jc.do("GET", "/api/audit", nil, &jAudit)
	op.do("GET", "/api/audit", nil, &opAudit)
	admin.do("GET", "/api/audit", nil, &adminAudit)
	for _, e := range jAudit {
		if e.CustomerCode == nil || *e.CustomerCode != "NSF" {
			t.Fatalf("admin do cliente viu evento fora da NSF: %+v", e)
		}
	}
	if len(jAudit) == 0 || len(opAudit) != len(adminAudit) {
		t.Fatalf("auditoria: júlia=%d operador=%d admin=%d", len(jAudit), len(opAudit), len(adminAudit))
	}

	// Operador global redefine TOTP de outra pessoa (função dele), mas não gerencia o acesso
	if st := op.do("POST", "/api/people/"+julia.ID+"/panel/reset-totp", map[string]any{}, nil); st != 200 {
		t.Fatalf("operador redefinindo TOTP: %d", st)
	}
	if st := jc.do("GET", "/api/customers", nil, nil); st != 401 {
		t.Fatalf("sessão da Júlia deveria cair após redefinir TOTP: %d", st)
	}

	// Auditoria é somente acréscimo
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
	other.do("POST", "/api/auth/login", map[string]string{"login": "marcos@onegate.systems", "password": opPW}, nil)
	code, _ := totp.Code(opSecret, opLoginAt) // o mesmo código que o Marcos já usou
	if st := other.do("POST", "/api/auth/totp", map[string]string{"code": code}, nil); st != 401 {
		t.Fatalf("reuso do código TOTP: %d", st)
	}

	// Código de recuperação: funciona uma vez
	rc := newClient(t, hs)
	rc.do("POST", "/api/auth/login", map[string]string{"login": "admin@onegate.systems", "password": adminPW}, nil)
	if st := rc.do("POST", "/api/auth/recovery", map[string]string{"code": codes[0]}, nil); st != 200 {
		t.Fatalf("código de recuperação: %d", st)
	}
	rc2 := newClient(t, hs)
	rc2.do("POST", "/api/auth/login", map[string]string{"login": "admin@onegate.systems", "password": adminPW}, nil)
	if st := rc2.do("POST", "/api/auth/recovery", map[string]string{"code": codes[0]}, nil); st != 401 {
		t.Fatalf("código de recuperação reutilizado: %d", st)
	}

	// Desativar a pessoa derruba as sessões
	if st := admin.do("PATCH", "/api/people/"+marcos.ID, map[string]any{"active": false}, nil); st != 200 {
		t.Fatalf("desativar: %d", st)
	}
	if st := op.do("GET", "/api/customers", nil, nil); st != 401 {
		t.Fatalf("sessão de pessoa desativada continua válida: %d", st)
	}
	if st := admin.do("POST", "/api/auth/logout", map[string]any{}, nil); st != 200 {
		t.Fatalf("logout: %d", st)
	}
	if st := admin.do("GET", "/api/auth/me", nil, nil); st != 401 {
		t.Fatalf("depois do logout: %d", st)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestLoginRateLimit(t *testing.T) {
	s, hs, _ := testServer(t)
	if _, err := s.CreatePanelUser(context.Background(), System, NewPanelUser{Login: "ana", Name: "Ana", Password: "senha-correta-123", TypeKey: "global_operator"}); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, hs)
	for i := 0; i < 5; i++ {
		c.do("POST", "/api/auth/login", map[string]string{"login": "ana@onegate.systems", "password": "errada-errada"}, nil)
	}
	if st := c.do("POST", "/api/auth/login", map[string]string{"login": "ana@onegate.systems", "password": "senha-correta-123"}, nil); st != 429 {
		t.Fatalf("deveria bloquear depois de 5 falhas: %d", st)
	}
}
