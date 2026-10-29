package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ajcorrea/onegate/internal/passhash"
)

func intp(v int) *int { return &v }

// samplePolicy monta a política de exemplo usada nos testes (cliente NetSul Fibra).
func samplePolicy(t *testing.T) *Policy {
	t.Helper()
	h, err := passhash.Hash("senha-forte-123")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	return &Policy{
		Version:  1,
		Customer: Customer{Code: "NSF", Name: "NetSul Fibra", MFA: MFATOTP, TrustWindowSeconds: 4 * 3600},
		DeviceGroups: []DeviceGroup{
			{Name: "Núcleo", MFA: MFATOTP, TrustWindowSeconds: intp(3600)},
			{Name: "Acesso", MFA: MFAOff},
			{Name: "Borda", MFA: MFAInherit},
		},
		Devices: []Device{
			{Name: "bng-01", Address: "10.0.0.1", Group: "Núcleo", MFA: MFAInherit, Secret: "chave-secreta-bng-01"},
			{Name: "sw-acesso", Address: "10.0.8.0/24", Group: "Acesso", MFA: MFAInherit, Secret: "chave-secreta-acesso"},
			{Name: "sw-acesso-12", Address: "10.0.8.12", Group: "Acesso", MFA: MFATOTP, CodeEntry: EntryAppend, Secret: "chave-secreta-sw-12x"},
			{Name: "rtr-borda", Address: "10.0.0.3", Group: "Borda", MFA: MFAInherit, Secret: "chave-secreta-borda1"},
		},
		UserGroups: []UserGroup{
			{Name: "NOC"},
			{Name: "Suporte N1"},
			{Name: "Terceirizados", RequireMFA: true, TrustWindowSeconds: intp(1800)},
			{Name: "Serviço"},
		},
		Users: []User{
			{Username: "alexandre.c", PasswordHash: h, TOTPSecret: secret, Groups: []string{"NOC"}},
			{Username: "suporte.n1", PasswordHash: h, TOTPSecret: secret, Groups: []string{"Suporte N1"}},
			{Username: "terceiro", PasswordHash: h, TOTPSecret: secret, Groups: []string{"Terceirizados"}},
			{Username: "backup-ncm", PasswordHash: h, Groups: []string{"Serviço"}, Service: true, AllowedSources: []string{"10.10.0.20"}},
			{Username: "inativo", PasswordHash: h, Groups: []string{"NOC"}, Disabled: true},
		},
		Rules: []Rule{
			{Name: "NOC total", UserGroups: []string{"NOC"}, Action: Allow, PrivLevel: 15},
			{Name: "Suporte leitura", UserGroups: []string{"Suporte N1"}, Action: Allow, PrivLevel: 5,
				Commands: CommandPolicy{Allow: []string{"display *", "show *", "ping *"}, Deny: []string{"display current-configuration *"}}},
			{Name: "Serviço backup", UserGroups: []string{"Serviço"}, Action: Allow, PrivLevel: 3,
				Commands: CommandPolicy{Allow: []string{"display current-configuration", "screen-length 0 temporary"}}},
			{Name: "Terceiros no acesso", UserGroups: []string{"Terceirizados"}, DeviceGroups: []string{"Acesso"}, Action: Allow, PrivLevel: 3},
			{Name: "Padrão", Action: Deny},
		},
	}
}

func compileSample(t *testing.T) *Engine {
	t.Helper()
	e, err := Compile(samplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func dev(t *testing.T, e *Engine, ip string) *Device {
	t.Helper()
	d, ok := e.DeviceFor(netip.MustParseAddr(ip))
	if !ok {
		t.Fatalf("equipamento %s não encontrado", ip)
	}
	return d
}

func TestDeviceLookupPrefersMostSpecific(t *testing.T) {
	e := compileSample(t)
	if d := dev(t, e, "10.0.8.12"); d.Name != "sw-acesso-12" {
		t.Fatalf("esperava sw-acesso-12, veio %s", d.Name)
	}
	if d := dev(t, e, "10.0.8.40"); d.Name != "sw-acesso" {
		t.Fatalf("esperava sw-acesso (faixa), veio %s", d.Name)
	}
	if _, ok := e.DeviceFor(netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("IP desconhecido não pode virar equipamento")
	}
}

func TestMFAInheritanceAndHardening(t *testing.T) {
	e := compileSample(t)
	cases := []struct {
		user, ip string
		required bool
		window   time.Duration
		entry    CodeEntry
	}{
		{"alexandre.c", "10.0.0.1", true, time.Hour, EntryPrompt},      // herdado do grupo Núcleo (1 h)
		{"alexandre.c", "10.0.8.40", false, 0, EntryPrompt},            // grupo Acesso: desligado
		{"alexandre.c", "10.0.8.12", true, 4 * time.Hour, EntryAppend}, // equipamento força TOTP; janela do cliente
		{"alexandre.c", "10.0.0.3", true, 4 * time.Hour, EntryPrompt},  // Borda herda do cliente
		{"terceiro", "10.0.8.40", true, 30 * time.Minute, EntryPrompt}, // grupo de técnicos endurece
		{"terceiro", "10.0.0.1", true, 30 * time.Minute, EntryPrompt},  // mais restritivo vence (30 min < 1 h)
		{"backup-ncm", "10.0.0.1", false, 0, EntryPrompt},              // conta de serviço
	}
	for _, c := range cases {
		got := e.MFAFor(c.user, dev(t, e, c.ip))
		if got.Required != c.required || got.TrustWindow != c.window || got.Entry != c.entry {
			t.Errorf("%s@%s: got %+v, want required=%v window=%v entry=%s", c.user, c.ip, got, c.required, c.window, c.entry)
		}
	}
}

func TestCommandAuthorization(t *testing.T) {
	e := compileSample(t)
	bng := dev(t, e, "10.0.0.1")
	cases := []struct {
		user, cmd string
		allowed   bool
	}{
		{"alexandre.c", "system-view", true},
		{"suporte.n1", "display interface brief", true},
		{"suporte.n1", "DISPLAY   interface", true},
		{"suporte.n1", "display", true},
		{"suporte.n1", "display current-configuration", false},
		{"suporte.n1", "system-view", false},
		{"suporte.n1", "reset bgp all", false},
		{"backup-ncm", "display current-configuration", true},
		{"backup-ncm", "display current-configuration | include x", false},
		{"terceiro", "display version", false}, // só tem regra no grupo Acesso
		{"desconhecido", "display version", false},
	}
	for _, c := range cases {
		got := e.AuthorizeCommand(c.user, bng, c.cmd)
		if got.Allowed != c.allowed {
			t.Errorf("%s %q: allowed=%v (%s), want %v", c.user, c.cmd, got.Allowed, got.Reason, c.allowed)
		}
	}
	if d := e.AuthorizeSession("suporte.n1", bng); !d.Allowed || d.PrivLevel != 5 {
		t.Errorf("sessão do suporte: %+v", d)
	}
	if d := e.AuthorizeSession("terceiro", bng); d.Allowed {
		t.Errorf("terceiro não pode abrir sessão no núcleo: %+v", d)
	}
}

func TestSourceRestriction(t *testing.T) {
	e := compileSample(t)
	if !e.SourceAllowed("backup-ncm", "10.10.0.20") || !e.SourceAllowed("backup-ncm", "10.10.0.20:51022") {
		t.Fatal("origem permitida rejeitada")
	}
	if e.SourceAllowed("backup-ncm", "10.10.0.21") || e.SourceAllowed("backup-ncm", "tty0") {
		t.Fatal("origem não permitida aceita")
	}
	if !e.SourceAllowed("alexandre.c", "tty0") {
		t.Fatal("usuário sem restrição deve ser aceito de qualquer origem")
	}
}

func TestValidationErrors(t *testing.T) {
	p := samplePolicy(t)
	p.Devices[0].Secret = "curta"
	p.Devices[1].Group = "Inexistente"
	p.Users[0].PasswordHash = "texto-puro"
	p.Users[3].AllowedSources = nil
	p.Rules[0].Action = "talvez"
	_, err := Compile(p)
	if err == nil {
		t.Fatal("política inválida foi aceita")
	}
	for _, want := range []string{"16 caracteres", "grupo inexistente", "Argon2id", "allowed_sources", "allow ou deny"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("erro deveria mencionar %q: %v", want, err)
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
