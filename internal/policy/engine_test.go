package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ajcorrea/onegate/internal/passhash"
)

func intp(v int) *int { return &v }

const (
	gdom = "onegate.systems"
	cdom = "netsulfibra.com.br"
)

// samplePolicy monta a política de exemplo dos testes (cliente NetSul Fibra), igual ao mockup.
func samplePolicy(t *testing.T) *Policy {
	t.Helper()
	h, err := passhash.Hash("senha-forte-123")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	return &Policy{
		Format:       FormatVersion,
		Version:      7,
		GlobalDomain: gdom,
		Customer:     Customer{Code: "NSF", Name: "NetSul Fibra", Domain: cdom, MFA: MFATOTP, TrustWindowSeconds: 4 * 3600},
		DeviceGroups: []DeviceGroup{
			{Name: "Núcleo", MFA: MFATOTP, TrustWindowSeconds: intp(3600)},
			{Name: "Acesso", MFA: MFAOff},
			{Name: "Borda", MFA: MFAInherit},
		},
		Devices: []Device{
			{Name: "bng-01", Address: "10.0.0.1", Groups: []string{"Núcleo"}, Vendor: "Huawei", Secret: "chave-secreta-bng-01"},
			{Name: "sw-acesso", Address: "10.0.8.0/24", Groups: []string{"Acesso"}, Vendor: "Datacom", Secret: "chave-secreta-acesso"},
			{Name: "sw-acesso-12", Address: "10.0.8.12", Groups: []string{"Acesso"}, Vendor: "Datacom", MFA: MFATOTP, CodeEntry: EntryAppend, Secret: "chave-secreta-sw-12x"},
			{Name: "edge-mk-01", Address: "10.0.0.3", Groups: []string{"Borda"}, Vendor: "MikroTik", Secret: "chave-secreta-borda1"},
		},
		UserGroups: []UserGroup{
			{Name: "NOC@" + gdom},
			{Name: "Suporte N1@" + cdom},
			{Name: "Terceirizados@" + cdom},
			{Name: "Contas de serviço@" + cdom},
		},
		Users: []User{
			{Username: "alexandre@" + gdom, PasswordHash: h, TOTPSecret: secret},
			{Username: "marcos@" + gdom, PasswordHash: h, TOTPSecret: secret, Groups: []string{"NOC@" + gdom}},
			{Username: "pedro.lima@" + cdom, PasswordHash: h, TOTPSecret: secret, Groups: []string{"Suporte N1@" + cdom}},
			{Username: "terceiro.redes@" + cdom, PasswordHash: h, TOTPSecret: secret, Groups: []string{"Terceirizados@" + cdom}},
			{Username: "backup-ncm@" + cdom, PasswordHash: h, Groups: []string{"Contas de serviço@" + cdom}},
			{Username: "inativo@" + cdom, PasswordHash: h, Disabled: true},
		},
		Networks: []Network{
			{Name: "Rede NOC ON TELECOM", CIDRs: []string{"10.20.0.0/16"}},
			{Name: "VPN técnicos", CIDRs: []string{"172.16.50.0/24"}},
			{Name: "Servidor de backup", CIDRs: []string{"10.10.0.20"}},
		},
		Profiles: []Profile{
			{Name: "Acesso total", PrivLevel: 15},
			{Name: "Somente leitura", PrivLevel: 5, Commands: CommandPolicy{
				Allow: []string{"display *", "show *", "ping *"}, Deny: []string{"display current-configuration *"}}},
			{Name: "Operação sem roteamento", PrivLevel: 15, Commands: CommandPolicy{
				Default: Allow, Deny: []string{"bgp *", "ospf *", "isis *", "route-policy *"}}},
			{Name: "Backup de configuração", PrivLevel: 3, Commands: CommandPolicy{
				Allow: []string{"screen-length 0 temporary", "display current-configuration"}}},
		},
		Schedules: []Schedule{
			{Name: "Comercial", Windows: []Window{{Days: []int{1, 2, 3, 4, 5}, Start: "08:00", End: "18:00"}}},
			{Name: "Plantão", Windows: []Window{{Days: []int{1, 2, 3, 4, 5, 6, 7}, Start: "18:00", End: "08:00"}}},
		},
		Rules: []Rule{
			{ID: "r1", Name: "Admin global", Scope: ScopeGlobal, Action: Allow, Who: []string{"user:alexandre@" + gdom},
				Where: []string{RefAll}, From: []string{RefAll}, What: "profile:Acesso total", MFA: RuleMFATOTP},
			{ID: "r2", Name: "Operadores globais (NOC)", Scope: ScopeGlobal, Action: Allow, Who: []string{"group:NOC@" + gdom},
				Where: []string{RefAll}, From: []string{"net:Rede NOC ON TELECOM", "net:VPN técnicos"}, What: "profile:Acesso total", MFA: RuleMFATOTP},
			{ID: "r3", Name: "Terceirizados fora do núcleo", Scope: ScopeCustomer, Action: Deny, Who: []string{"group:Terceirizados@" + cdom},
				Where: []string{"group:Núcleo"}, From: []string{RefAll}},
			{ID: "r4", Name: "Suporte N1: leitura", Scope: ScopeCustomer, Action: Allow, Who: []string{"group:Suporte N1@" + cdom},
				Where: []string{"group:Núcleo", "group:Borda", "group:Acesso"}, From: []string{"net:VPN técnicos"},
				What: "profile:Somente leitura", When: []string{"schedule:Comercial"}, MFA: RuleMFATOTP},
			{ID: "r5", Name: "Terceirizados no acesso", Scope: ScopeCustomer, Action: Allow, Who: []string{"group:Terceirizados@" + cdom},
				Where: []string{"vendor:Datacom"}, From: []string{RefAll}, What: "profile:Operação sem roteamento", When: []string{"schedule:Comercial"}},
			{ID: "r6", Name: "Backup de configuração", Scope: ScopeCustomer, Action: Allow, Who: []string{"group:Contas de serviço@" + cdom},
				Where: []string{RefAll}, From: []string{"net:Servidor de backup"}, What: "profile:Backup de configuração", MFA: RuleMFANone},
			{ID: "r7", Name: "Rascunho sem origem", Scope: ScopeCustomer, Action: Allow, Who: []string{RefAll},
				Where: []string{RefAll}, What: "profile:Acesso total"},
		},
	}
}

func mustEngine(t *testing.T, p *Policy) *Engine {
	t.Helper()
	e, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Quarta-feira, 10:00 em São Paulo (horário comercial) e 22:00 (fora).
var (
	sp, _    = time.LoadLocation("America/Sao_Paulo")
	business = time.Date(2026, 10, 28, 10, 0, 0, 0, sp)
	night    = time.Date(2026, 10, 28, 22, 0, 0, 0, sp)
)

func dev(t *testing.T, e *Engine, ip string) *Device {
	t.Helper()
	d, ok := e.DeviceFor(netip.MustParseAddr(ip))
	if !ok {
		t.Fatalf("sem equipamento para %s", ip)
	}
	return d
}

func TestDeviceLookupPrefersMostSpecific(t *testing.T) {
	e := mustEngine(t, samplePolicy(t))
	if d := dev(t, e, "10.0.8.12"); d.Name != "sw-acesso-12" {
		t.Errorf("10.0.8.12 = %s", d.Name)
	}
	if d := dev(t, e, "10.0.8.99"); d.Name != "sw-acesso" {
		t.Errorf("10.0.8.99 = %s", d.Name)
	}
	if _, ok := e.DeviceFor(netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("IP desconhecido não pode ter equipamento")
	}
}

func TestResolveUserCompletesDomain(t *testing.T) {
	e := mustEngine(t, samplePolicy(t))
	for typed, want := range map[string]string{
		"pedro.lima":                    "pedro.lima@" + cdom,
		"Pedro.Lima@NetSulFibra.com.br": "pedro.lima@" + cdom,
		"marcos":                        "marcos@" + gdom, // não existe no cliente: cai no global
		"marcos@" + gdom:                "marcos@" + gdom,
	} {
		u, ok := e.ResolveUser(typed)
		if !ok || u.Username != want {
			t.Errorf("ResolveUser(%q) = %v, %v; quer %s", typed, u, ok, want)
		}
	}
	if _, ok := e.ResolveUser("pedro.lima@valeconecta.com.br"); ok {
		t.Error("domínio de outro cliente não pode resolver")
	}
}

func TestEvaluateFirstMatchAndDefaultDeny(t *testing.T) {
	e := mustEngine(t, samplePolicy(t))
	bng := dev(t, e, "10.0.0.1")
	sw := dev(t, e, "10.0.8.40")
	cases := []struct {
		name, user, src string
		d               *Device
		at              time.Time
		allowed         bool
		rule            string
		contains        string
	}{
		{"admin global de qualquer lugar", "alexandre", "203.0.113.9", bng, night, true, "Admin global", "Acesso total"},
		{"NOC pela VPN", "marcos", "172.16.50.23", bng, night, true, "Operadores globais (NOC)", ""},
		{"NOC fora das faixas", "marcos", "203.0.113.9", bng, business, false, "", "nenhuma regra"},
		{"terceirizado no núcleo é negado pela regra", "terceiro.redes", "200.1.1.1", bng, business, false, "Terceirizados fora do núcleo", "nega"},
		{"terceirizado no Datacom em horário comercial", "terceiro.redes", "200.1.1.1", sw, business, true, "Terceirizados no acesso", ""},
		{"terceirizado fora do horário", "terceiro.redes", "200.1.1.1", sw, night, false, "", "nenhuma regra"},
		{"suporte pela VPN no horário", "pedro.lima", "172.16.50.8", sw, business, true, "Suporte N1: leitura", ""},
		{"suporte fora da VPN", "pedro.lima", "10.99.0.1", sw, business, false, "", "nenhuma regra"},
		{"backup do servidor", "backup-ncm", "10.10.0.20", bng, night, true, "Backup de configuração", ""},
		{"backup de outro IP", "backup-ncm", "10.10.0.21", bng, night, false, "", "nenhuma regra"},
		{"console não é IP", "pedro.lima", "tty0", sw, business, false, "", "nenhuma regra"},
		{"usuário desativado", "inativo", "172.16.50.8", sw, business, false, "", "desativado"},
		{"usuário desconhecido", "fulano", "172.16.50.8", sw, business, false, "", "desconhecido"},
	}
	for _, c := range cases {
		r := e.Evaluate(Request{User: c.user, Device: c.d, Source: c.src, Time: c.at})
		if r.Allowed != c.allowed || r.Rule != c.rule || !strings.Contains(r.Reason, c.contains) {
			t.Errorf("%s: allowed=%v rule=%q reason=%q", c.name, r.Allowed, r.Rule, r.Reason)
		}
	}
}

func TestIncompleteRuleNeverMatches(t *testing.T) {
	e := mustEngine(t, samplePolicy(t))
	// r7 tem Quem = Todos e Onde = Todos, mas De onde vazio: não pode liberar ninguém.
	r := e.Evaluate(Request{User: "pedro.lima", Device: dev(t, e, "10.0.8.40"), Source: "10.99.0.1", Time: night})
	if r.Allowed {
		t.Fatalf("regra incompleta liberou acesso: %+v", r)
	}
	last := r.Trail[len(r.Trail)-1]
	if last.Status != "incomplete" || !strings.Contains(last.Note, "De onde") {
		t.Errorf("rastro da regra incompleta = %+v", last)
	}
	if w := e.Warnings(); len(w) != 1 || !strings.Contains(w[0], "Rascunho sem origem") {
		t.Errorf("avisos = %v", w)
	}
}

func TestPredefinedNoneAndNever(t *testing.T) {
	p := samplePolicy(t)
	p.Rules = []Rule{
		{Name: "Ninguém", Scope: ScopeCustomer, Action: Allow, Who: []string{RefNone}, Where: []string{RefAll}, From: []string{RefAll}, What: "profile:Acesso total"},
		{Name: "Nenhum IP", Scope: ScopeCustomer, Action: Allow, Who: []string{RefAll}, Where: []string{RefAll}, From: []string{RefNone}, What: "profile:Acesso total"},
		{Name: "Desligada", Scope: ScopeCustomer, Action: Allow, Who: []string{RefAll}, Where: []string{RefAll}, From: []string{RefAll}, What: "profile:Acesso total", When: []string{RefNever}},
		{Name: "Só login", Scope: ScopeCustomer, Action: Allow, Who: []string{RefAll}, Where: []string{RefAll}, From: []string{RefAll}, What: RefNone, MFA: RuleMFANone},
	}
	e := mustEngine(t, p)
	req := Request{User: "pedro.lima", Device: dev(t, e, "10.0.0.1"), Source: "10.1.1.1", Time: business}
	r := e.Evaluate(req)
	if !r.Allowed || r.Rule != "Só login" || r.PrivLevel != 1 {
		t.Fatalf("esperava cair em 'Só login': %+v", r)
	}
	notes := []string{r.Trail[0].Note, r.Trail[1].Note, r.Trail[2].Note}
	if notes[0] != "quem não corresponde" || !strings.Contains(notes[1], "fora das faixas") || notes[2] != "quando = Nunca" {
		t.Errorf("notas = %q", notes)
	}
	if c := e.AuthorizeCommand(req, "display version"); c.Allowed {
		t.Error("perfil Nenhum comando não pode executar nada")
	}
}

func TestAllInCustomerRuleIsScopedToCustomerDomain(t *testing.T) {
	p := samplePolicy(t)
	p.Rules = []Rule{{Name: "Todos do cliente", Scope: ScopeCustomer, Action: Allow, Who: []string{RefAll},
		Where: []string{RefAll}, From: []string{RefAll}, What: "profile:Somente leitura"}}
	e := mustEngine(t, p)
	d := dev(t, e, "10.0.0.1")
	if r := e.Evaluate(Request{User: "pedro.lima", Device: d, Source: "1.1.1.1", Time: business}); !r.Allowed {
		t.Errorf("usuário do cliente deveria entrar: %s", r.Reason)
	}
	if r := e.Evaluate(Request{User: "marcos", Device: d, Source: "1.1.1.1", Time: business}); r.Allowed {
		t.Error("\"Todos\" numa regra do cliente não pode incluir usuários globais")
	}
	p.Rules[0].Scope = ScopeGlobal
	e = mustEngine(t, p)
	if r := e.Evaluate(Request{User: "marcos", Device: d, Source: "1.1.1.1", Time: business}); !r.Allowed {
		t.Error("\"Todos\" numa regra global inclui todos")
	}
}

func TestScheduleAcrossMidnight(t *testing.T) {
	w, err := compileWindow(Window{Days: []int{5}, Start: "18:00", End: "08:00"}) // sexta 18h → sábado 08h
	if err != nil {
		t.Fatal(err)
	}
	for at, want := range map[time.Time]bool{
		time.Date(2026, 10, 30, 19, 0, 0, 0, sp): true,  // sexta 19h
		time.Date(2026, 10, 31, 7, 59, 0, 0, sp): true,  // sábado 07:59
		time.Date(2026, 10, 31, 8, 0, 0, 0, sp):  false, // sábado 08:00
		time.Date(2026, 10, 30, 7, 0, 0, 0, sp):  false, // sexta 07h (depois de quinta, que não está)
		time.Date(2026, 10, 31, 19, 0, 0, 0, sp): false, // sábado 19h
	} {
		if got := w.contains(at); got != want {
			t.Errorf("%s: %v, quer %v", at.Format("Mon 15:04"), got, want)
		}
	}
}

func TestEvaluateUsesCustomerTimezone(t *testing.T) {
	e := mustEngine(t, samplePolicy(t))
	sw := dev(t, e, "10.0.8.40")
	// 12:00 UTC = 09:00 em São Paulo (comercial)
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	if r := e.Evaluate(Request{User: "pedro.lima", Device: sw, Source: "172.16.50.8", Time: at}); !r.Allowed {
		t.Errorf("deveria estar no horário comercial: %s", r.Reason)
	}
}

func TestMFAByRuleAndInheritance(t *testing.T) {
	p := samplePolicy(t)
	p.Rules = append([]Rule{{Name: "Terceiros segue equipamento", Scope: ScopeCustomer, Action: Allow,
		Who: []string{"group:Terceirizados@" + cdom}, Where: []string{RefAll}, From: []string{RefAll}, What: "profile:Somente leitura"}}, p.Rules...)
	// regras globais primeiro
	p.Rules[0], p.Rules[1], p.Rules[2] = p.Rules[1], p.Rules[2], p.Rules[0]
	e := mustEngine(t, p)
	at := business
	cases := []struct {
		user, ip string
		req      bool
		window   time.Duration
		entry    CodeEntry
	}{
		{"terceiro.redes", "10.0.0.1", true, time.Hour, EntryPrompt},      // grupo Núcleo: totp, 1h
		{"terceiro.redes", "10.0.8.40", false, 0, EntryPrompt},            // grupo Acesso: off
		{"terceiro.redes", "10.0.8.12", true, 4 * time.Hour, EntryAppend}, // equipamento totp, janela do cliente
		{"terceiro.redes", "10.0.0.3", true, 4 * time.Hour, EntryPrompt},  // Borda herda do cliente
		{"alexandre", "10.0.8.40", true, 0, EntryPrompt},                  // regra TOTP vence Acesso off
		{"backup-ncm", "10.0.0.1", false, 0, EntryPrompt},                 // regra sem MFA
	}
	for _, c := range cases {
		src := "1.1.1.1"
		if strings.HasPrefix(c.user, "backup") {
			src = "10.10.0.20"
		}
		r := e.Evaluate(Request{User: c.user, Device: dev(t, e, c.ip), Source: src, Time: at})
		if !r.Allowed {
			t.Fatalf("%s em %s: %s", c.user, c.ip, r.Reason)
		}
		if r.MFA.Required != c.req || r.MFA.Entry != c.entry || (c.window != 0 && r.MFA.TrustWindow != c.window) {
			t.Errorf("%s em %s: MFA = %+v", c.user, c.ip, r.MFA)
		}
	}
}

func TestCommandAuthorization(t *testing.T) {
	e := mustEngine(t, samplePolicy(t))
	sw := dev(t, e, "10.0.8.40")
	sup := Request{User: "pedro.lima", Device: sw, Source: "172.16.50.8", Time: business}
	ter := Request{User: "terceiro.redes", Device: sw, Source: "1.1.1.1", Time: business}
	cases := []struct {
		req  Request
		cmd  string
		want bool
	}{
		{sup, "display interface brief", true},
		{sup, "DISPLAY   version", true},
		{sup, "display", true},
		{sup, "display current-configuration", false},
		{sup, "system-view", false},
		{ter, "interface gigabitethernet 0/0/1", true},
		{ter, "bgp 65000", false},
		{ter, "ospf", false},
	}
	for _, c := range cases {
		if got := e.AuthorizeCommand(c.req, c.cmd); got.Allowed != c.want {
			t.Errorf("%s: %q = %v (%s)", c.req.User, c.cmd, got.Allowed, got.Reason)
		}
	}
	// fora do horário, o comando também é negado (regra reavaliada a cada comando)
	sup.Time = night
	if got := e.AuthorizeCommand(sup, "display version"); got.Allowed {
		t.Error("comando fora do horário deveria ser negado")
	}
}

func TestValidationErrors(t *testing.T) {
	p := samplePolicy(t)
	p.Rules = append(p.Rules,
		Rule{Name: "Grupo errado", Scope: ScopeCustomer, Action: Allow, Who: []string{"group:Fantasma@" + cdom}, Where: []string{RefAll}, From: []string{RefAll}, What: "profile:Acesso total"},
		Rule{Name: "Global depois", Scope: ScopeGlobal, Action: Deny, Who: []string{RefAll}, Where: []string{RefAll}, From: []string{RefAll}},
		Rule{Name: "Perfil errado", Scope: ScopeCustomer, Action: Allow, Who: []string{RefAll}, Where: []string{RefAll}, From: []string{"cidr:10.0.0.0/33"}, What: "profile:Nada"},
	)
	p.Users[0].PasswordHash = "texto-puro"
	p.Devices[0].Secret = "curta"
	p.Schedules[0].Windows[0].Start = "25:00"
	_, err := Compile(p)
	if err == nil {
		t.Fatal("esperava erro de validação")
	}
	for _, want := range []string{"Fantasma", "globais precisam vir antes", "faixa inválida", "perfil de comandos inexistente", "Argon2id", "16 caracteres", "hora inválida"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("erro não menciona %q:\n%v", want, err)
		}
	}
}

func TestMaskSecrets(t *testing.T) {
	cases := map[string]string{
		"local-user admin password irreversible-cipher Abc@123": "local-user admin password irreversible-cipher ****",
		"snmp-agent community read cipher Publ1c":               "snmp-agent community **** cipher ****",
		"mysql -uroot -pSenha123 banco":                         "mysql -uroot -p**** banco",
		"display interface brief":                               "display interface brief",
		"tool --password=xyz":                                   "tool --password=****",
	}
	for in, want := range cases {
		if got := MaskSecrets(in); got != want {
			t.Errorf("MaskSecrets(%q) = %q, want %q", in, got, want)
		}
	}
}
