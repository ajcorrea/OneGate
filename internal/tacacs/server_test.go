package tacacs

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nwaples/tacplus"

	"github.com/ajcorrea/onegate/internal/edgelog"
	"github.com/ajcorrea/onegate/internal/passhash"
	"github.com/ajcorrea/onegate/internal/policy"
	"github.com/ajcorrea/onegate/internal/totp"
)

const (
	testSecret = "chave-compartilhada-de-teste"
	totpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	password   = "senha-forte-123"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

type fixture struct {
	t      *testing.T
	srv    *Server
	log    *edgelog.MemoryLogger
	clk    *clock
	client *tacplus.Client
}

// newFixture sobe um Edge em 127.0.0.1 cujo único equipamento é o próprio 127.0.0.1.
func newFixture(t *testing.T, mfa policy.MFAMode, entry policy.CodeEntry, deviceAddr string) *fixture {
	t.Helper()
	h, err := passhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	window := 3600
	p := &policy.Policy{
		Format:       policy.FormatVersion,
		Version:      7,
		GlobalDomain: "onegate.systems",
		Customer:     policy.Customer{Code: "NSF", Name: "NetSul Fibra", Domain: "netsulfibra.com.br", MFA: policy.MFAOff},
		DeviceGroups: []policy.DeviceGroup{{Name: "Núcleo", MFA: mfa, TrustWindowSeconds: &window}},
		Devices: []policy.Device{{Name: "bng-01", Address: deviceAddr, Groups: []string{"Núcleo"}, Vendor: "Huawei",
			MFA: policy.MFAInherit, CodeEntry: entry, Secret: testSecret}},
		UserGroups: []policy.UserGroup{{Name: "NOC@onegate.systems"}, {Name: "Suporte N1@netsulfibra.com.br"}},
		Users: []policy.User{
			{Username: "alexandre.c@onegate.systems", PasswordHash: h, TOTPSecret: totpSecret, Groups: []string{"NOC@onegate.systems"}},
			{Username: "suporte.n1@netsulfibra.com.br", PasswordHash: h, TOTPSecret: totpSecret, Groups: []string{"Suporte N1@netsulfibra.com.br"}},
		},
		Networks: []policy.Network{{Name: "Rede NOC", CIDRs: []string{"10.20.0.0/16"}}},
		Profiles: []policy.Profile{
			{Name: "Acesso total", PrivLevel: 15},
			{Name: "Somente leitura", PrivLevel: 5, Commands: policy.CommandPolicy{Allow: []string{"display *"}}},
		},
		Rules: []policy.Rule{
			{Name: "NOC total", Scope: policy.ScopeGlobal, Action: policy.Allow, Who: []string{"group:NOC@onegate.systems"},
				Where: []string{policy.RefAll}, From: []string{policy.RefAll}, What: "profile:Acesso total"},
			{Name: "Suporte leitura", Scope: policy.ScopeCustomer, Action: policy.Allow, Who: []string{"group:Suporte N1@netsulfibra.com.br"},
				Where: []string{"group:Núcleo"}, From: []string{"net:Rede NOC"}, What: "profile:Somente leitura"},
		},
	}
	eng, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	log := &edgelog.MemoryLogger{}
	srv := New(eng, log)
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	srv.now = clk.now

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = l.Close() })

	return &fixture{t: t, srv: srv, log: log, clk: clk, client: &tacplus.Client{
		Addr:       l.Addr().String(),
		ConnConfig: tacplus.ConnConfig{Secret: []byte(testSecret), ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, Log: func(...any) {}},
	}}
}

func (f *fixture) code() string {
	c, err := totp.Code(totpSecret, f.clk.now())
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

// asciiLogin simula um login interativo: responde aos prompts na ordem em que chegam.
func (f *fixture) asciiLogin(user, remAddr string, answers ...string) (uint8, []string) {
	f.t.Helper()
	rep, sess, err := f.client.SendAuthenStart(ctx(f.t), &tacplus.AuthenStart{
		Action: tacplus.AuthenActionLogin, AuthenType: tacplus.AuthenTypeASCII, AuthenService: tacplus.AuthenServiceLogin,
		PrivLvl: 1, User: user, Port: "vty0", RemAddr: remAddr,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	var prompts []string
	for sess != nil {
		prompts = append(prompts, rep.ServerMsg)
		if len(answers) == 0 {
			f.t.Fatalf("servidor pediu %q sem resposta prevista", rep.ServerMsg)
		}
		rep, err = sess.Continue(ctx(f.t), answers[0])
		answers = answers[1:]
		if err != nil {
			f.t.Fatal(err)
		}
		if rep.Status == tacplus.AuthenStatusPass || rep.Status == tacplus.AuthenStatusFail || rep.Status == tacplus.AuthenStatusError {
			sess.Close()
			sess = nil
		}
	}
	return rep.Status, prompts
}

func (f *fixture) papLogin(user, remAddr, pass string) uint8 {
	f.t.Helper()
	rep, _, err := f.client.SendAuthenStart(ctx(f.t), &tacplus.AuthenStart{
		Action: tacplus.AuthenActionLogin, AuthenType: tacplus.AuthenTypePAP, AuthenService: tacplus.AuthenServiceLogin,
		PrivLvl: 1, User: user, Port: "vty0", RemAddr: remAddr, Data: []byte(pass),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return rep.Status
}

func (f *fixture) lastEvent() edgelog.Event {
	ev := f.log.Events()
	if len(ev) == 0 {
		f.t.Fatal("nenhum evento registrado")
	}
	return ev[len(ev)-1]
}

func TestASCIILoginWithPromptMFAAndTrustWindow(t *testing.T) {
	f := newFixture(t, policy.MFATOTP, policy.EntryPrompt, "127.0.0.1")

	st, prompts := f.asciiLogin("alexandre.c", "10.20.1.5", password, f.code())
	if st != tacplus.AuthenStatusPass {
		t.Fatalf("login com senha e TOTP falhou: %+v", f.lastEvent())
	}
	if len(prompts) != 2 || prompts[0] != "Senha: " || prompts[1] != "Código MFA: " {
		t.Fatalf("prompts inesperados: %q", prompts)
	}
	if ev := f.lastEvent(); ev.MFA != "totp" || ev.Priv != 15 || ev.Device != "bng-01" || ev.Customer != "NSF" {
		t.Fatalf("evento inesperado: %+v", ev)
	}

	// Dentro da janela, a partir do mesmo IP: só a senha.
	f.clk.add(10 * time.Minute)
	st, prompts = f.asciiLogin("alexandre.c", "10.20.1.5", password)
	if st != tacplus.AuthenStatusPass || len(prompts) != 1 || f.lastEvent().MFA != "trusted" {
		t.Fatalf("janela de confiança não funcionou: st=%d prompts=%q ev=%+v", st, prompts, f.lastEvent())
	}

	// De outro IP a janela não vale: pede código de novo (num passo novo, para não cair no anti-reuso).
	f.clk.add(30 * time.Second)
	st, _ = f.asciiLogin("alexandre.c", "10.20.1.99", password, f.code())
	if st != tacplus.AuthenStatusPass || f.lastEvent().MFA != "totp" {
		t.Fatalf("outro IP deveria exigir TOTP e aceitar: %+v", f.lastEvent())
	}

	// Depois da janela, volta a pedir o código.
	f.clk.add(61 * time.Minute)
	_, prompts = f.asciiLogin("alexandre.c", "10.20.1.5", password, f.code())
	if len(prompts) != 2 {
		t.Fatalf("depois da janela deveria pedir o código: %q", prompts)
	}
}

func TestTOTPCannotBeReused(t *testing.T) {
	f := newFixture(t, policy.MFATOTP, policy.EntryPrompt, "127.0.0.1")
	code := f.code()
	if st, _ := f.asciiLogin("alexandre.c", "10.20.1.5", password, code); st != tacplus.AuthenStatusPass {
		t.Fatal("primeiro uso deveria passar")
	}
	if st, _ := f.asciiLogin("alexandre.c", "10.20.1.6", password, code); st != tacplus.AuthenStatusFail {
		t.Fatal("o mesmo código não pode ser aceito duas vezes")
	}
	if r := f.lastEvent().Reason; r != "código TOTP já utilizado" {
		t.Fatalf("motivo inesperado: %q", r)
	}
}

func TestWrongPasswordAndWrongCode(t *testing.T) {
	f := newFixture(t, policy.MFATOTP, policy.EntryPrompt, "127.0.0.1")
	if st, prompts := f.asciiLogin("alexandre.c", "10.20.1.5", "errada"); st != tacplus.AuthenStatusFail || len(prompts) != 1 {
		t.Fatalf("senha errada: st=%d prompts=%q", st, prompts)
	}
	if st, _ := f.asciiLogin("alexandre.c", "10.20.1.5", password, "000000"); st != tacplus.AuthenStatusFail {
		t.Fatal("código errado aceito")
	}
	if st, _ := f.asciiLogin("ninguem", "10.20.1.5", password); st != tacplus.AuthenStatusFail {
		t.Fatal("usuário desconhecido aceito")
	}
}

func TestPAPWithAppendedCode(t *testing.T) {
	f := newFixture(t, policy.MFATOTP, policy.EntryAppend, "127.0.0.1")
	if st := f.papLogin("alexandre.c", "10.20.1.5", password); st != tacplus.AuthenStatusFail {
		t.Fatal("PAP sem código deveria falhar quando o MFA é exigido")
	}
	f.clk.add(30 * time.Second)
	if st := f.papLogin("alexandre.c", "10.20.1.5", password+f.code()); st != tacplus.AuthenStatusPass {
		t.Fatalf("PAP com senha+código falhou: %+v", f.lastEvent())
	}
	// Dentro da janela: aceita só a senha e também senha+código (hábito do técnico).
	if st := f.papLogin("alexandre.c", "10.20.1.5", password); st != tacplus.AuthenStatusPass {
		t.Fatal("janela de confiança com PAP não funcionou")
	}
	if st := f.papLogin("alexandre.c", "10.20.1.5", password+"123456"); st != tacplus.AuthenStatusPass {
		t.Fatal("senha+código dentro da janela deveria ser aceito")
	}
}

func TestNoMFAWhenDisabled(t *testing.T) {
	f := newFixture(t, policy.MFAOff, policy.EntryPrompt, "127.0.0.1")
	st, prompts := f.asciiLogin("alexandre.c", "10.20.1.5", password)
	if st != tacplus.AuthenStatusPass || len(prompts) != 1 || f.lastEvent().MFA != "none" {
		t.Fatalf("sem MFA: st=%d prompts=%q ev=%+v", st, prompts, f.lastEvent())
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	f := newFixture(t, policy.MFAOff, policy.EntryPrompt, "127.0.0.1")
	for i := 0; i < 5; i++ {
		f.papLogin("alexandre.c", "10.20.1.5", "errada")
	}
	if st := f.papLogin("alexandre.c", "10.20.1.5", password); st != tacplus.AuthenStatusFail {
		t.Fatal("deveria estar bloqueado depois de 5 falhas")
	}
	if r := f.lastEvent().Reason; !strings.Contains(r, "excesso de falhas") {
		t.Fatalf("motivo inesperado: %q", r)
	}
	if st := f.papLogin("alexandre.c", "10.20.1.6", password); st != tacplus.AuthenStatusPass {
		t.Fatal("o bloqueio é por usuário+origem; outra origem deve funcionar")
	}
	f.clk.add(11 * time.Minute)
	if st := f.papLogin("alexandre.c", "10.20.1.5", password); st != tacplus.AuthenStatusPass {
		t.Fatal("o bloqueio deveria expirar")
	}
}

func TestAuthorization(t *testing.T) {
	f := newFixture(t, policy.MFAOff, policy.EntryPrompt, "127.0.0.1")
	author := func(user string, arg ...string) *tacplus.AuthorResponse {
		r, err := f.client.SendAuthorRequest(ctx(t), &tacplus.AuthorRequest{
			AuthenMethod: tacplus.AuthenMethodTACACSPlus, AuthenType: tacplus.AuthenTypeASCII,
			AuthenService: tacplus.AuthenServiceLogin, User: user, Port: "vty0", RemAddr: "10.20.1.5", Arg: arg,
		})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := author("suporte.n1", "service=shell", "cmd=")
	if r.Status != tacplus.AuthorStatusPassAdd || len(r.Arg) != 1 || r.Arg[0] != "priv-lvl=5" {
		t.Fatalf("início de sessão: %+v", r)
	}
	if r := author("suporte.n1", "service=shell", "cmd=display", "cmd-arg=interface", "cmd-arg=brief", "cmd-arg=<cr>"); r.Status != tacplus.AuthorStatusPassAdd {
		t.Fatalf("display deveria ser permitido: %+v", r)
	}
	if r := author("suporte.n1", "service=shell", "cmd=system-view", "cmd-arg=<cr>"); r.Status != tacplus.AuthorStatusFail {
		t.Fatalf("system-view deveria ser negado: %+v", r)
	}
	if ev := f.lastEvent(); ev.Command != "system-view" || ev.Result != "fail" || ev.Rule != "Suporte leitura" {
		t.Fatalf("evento de autorização: %+v", ev)
	}
	if r := author("alexandre.c", "service=shell", "cmd=system-view"); r.Status != tacplus.AuthorStatusPassAdd {
		t.Fatalf("NOC deveria poder tudo: %+v", r)
	}
}

func TestRuleSourceAndDomain(t *testing.T) {
	f := newFixture(t, policy.MFAOff, policy.EntryPrompt, "127.0.0.1")
	// Usuário curto e completo levam à mesma conta; o evento grava o nome completo.
	if st, _ := f.asciiLogin("suporte.n1", "10.20.1.5", password); st != tacplus.AuthenStatusPass {
		t.Fatalf("login curto: %+v", f.lastEvent())
	}
	if ev := f.lastEvent(); ev.User != "suporte.n1@netsulfibra.com.br" || ev.Rule != "Suporte leitura" || ev.Priv != 5 {
		t.Fatalf("evento: %+v", ev)
	}
	if st, _ := f.asciiLogin("Suporte.N1@NetSulFibra.com.br", "10.20.1.5", password); st != tacplus.AuthenStatusPass {
		t.Fatal("login com domínio deveria passar")
	}
	// Fora da faixa da regra: nenhuma regra corresponde e nega, sem pedir MFA.
	if st, _ := f.asciiLogin("suporte.n1", "192.0.2.10", password); st != tacplus.AuthenStatusFail {
		t.Fatal("origem fora da regra deveria ser negada")
	}
	if r := f.lastEvent().Reason; !strings.Contains(r, "nenhuma regra") {
		t.Fatalf("motivo: %q", r)
	}
	// Domínio de outro cliente não resolve.
	if st, _ := f.asciiLogin("suporte.n1@valeconecta.com.br", "10.20.1.5", password); st != tacplus.AuthenStatusFail {
		t.Fatal("domínio de outro cliente deveria falhar")
	}
}

func TestAccountingMasksSecrets(t *testing.T) {
	f := newFixture(t, policy.MFAOff, policy.EntryPrompt, "127.0.0.1")
	_, err := f.client.SendAcctRequest(ctx(t), &tacplus.AcctRequest{
		Flags: tacplus.AcctFlagStop, AuthenMethod: tacplus.AuthenMethodTACACSPlus, PrivLvl: 15,
		AuthenType: tacplus.AuthenTypeASCII, AuthenService: tacplus.AuthenServiceLogin,
		User: "alexandre.c", Port: "vty0", RemAddr: "10.20.1.5",
		Arg: []string{"task_id=42", "service=shell", "cmd=local-user", "cmd-arg=admin", "cmd-arg=password", "cmd-arg=irreversible-cipher", "cmd-arg=Segredo@1", "cmd-arg=<cr>"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := f.lastEvent()
	if ev.Kind != "acct" || ev.Result != "stop" || ev.TaskID != "42" || ev.Priv != 15 {
		t.Fatalf("evento de accounting: %+v", ev)
	}
	if ev.Command != "local-user admin password irreversible-cipher ****" {
		t.Fatalf("segredo não foi mascarado: %q", ev.Command)
	}
}

func TestUnknownDeviceIsRejected(t *testing.T) {
	f := newFixture(t, policy.MFAOff, policy.EntryPrompt, "10.9.9.9")
	_, _, err := f.client.SendAuthenStart(ctx(t), &tacplus.AuthenStart{
		Action: tacplus.AuthenActionLogin, AuthenType: tacplus.AuthenTypePAP, AuthenService: tacplus.AuthenServiceLogin,
		User: "alexandre.c", Data: []byte(password),
	})
	if err == nil {
		t.Fatal("conexão de equipamento não cadastrado deveria ser recusada")
	}
	if ev := f.lastEvent(); ev.Reason != "equipamento não cadastrado" || ev.DeviceIP != "127.0.0.1" {
		t.Fatalf("evento inesperado: %+v", ev)
	}
}

func TestWrongSharedSecret(t *testing.T) {
	f := newFixture(t, policy.MFAOff, policy.EntryPrompt, "127.0.0.1")
	f.client.ConnConfig.Secret = []byte("chave-errada-xxxxxxxx")
	rep, _, err := f.client.SendAuthenStart(ctx(t), &tacplus.AuthenStart{
		Action: tacplus.AuthenActionLogin, AuthenType: tacplus.AuthenTypePAP, AuthenService: tacplus.AuthenServiceLogin,
		User: "alexandre.c", Data: []byte(password),
	})
	if err == nil && rep.Status == tacplus.AuthenStatusPass {
		t.Fatal("chave errada não pode autenticar")
	}
}
