package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ajcorrea/onegate/internal/passhash"
	"github.com/ajcorrea/onegate/internal/totp"
)

// Engine é a política compilada e validada, pronta para decisões.
type Engine struct {
	p         *Policy
	devices   []compiledDevice
	devGroups map[string]*DeviceGroup
	usrGroups map[string]*UserGroup
	users     map[string]*compiledUser
	rules     []compiledRule
}

type compiledDevice struct {
	prefix netip.Prefix
	d      *Device
}

type compiledUser struct {
	u       *User
	sources []netip.Prefix
	groups  map[string]bool
}

type compiledRule struct {
	r        *Rule
	users    map[string]bool
	devices  map[string]bool
	commands *commandMatcher
}

// Compile valida a política e prepara as estruturas de decisão.
func Compile(p *Policy) (*Engine, error) {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	e := &Engine{
		p:         p,
		devGroups: map[string]*DeviceGroup{},
		usrGroups: map[string]*UserGroup{},
		users:     map[string]*compiledUser{},
	}
	if p.Customer.Code == "" {
		add("customer.code é obrigatório")
	}
	if p.Customer.MFA != MFAOff && p.Customer.MFA != MFATOTP {
		add("customer.mfa deve ser \"off\" ou \"totp\"")
	}
	if p.Customer.TrustWindowSeconds < 0 {
		add("customer.trust_window_seconds não pode ser negativo")
	}
	for i := range p.DeviceGroups {
		g := &p.DeviceGroups[i]
		if g.Name == "" || e.devGroups[g.Name] != nil {
			add("device_groups[%d]: nome vazio ou repetido", i)
			continue
		}
		if !validMode(g.MFA, true) {
			add("device_groups %q: mfa inválido %q", g.Name, g.MFA)
		}
		if g.TrustWindowSeconds != nil && *g.TrustWindowSeconds < 0 {
			add("device_groups %q: janela negativa", g.Name)
		}
		e.devGroups[g.Name] = g
	}
	for i := range p.UserGroups {
		g := &p.UserGroups[i]
		if g.Name == "" || e.usrGroups[g.Name] != nil {
			add("user_groups[%d]: nome vazio ou repetido", i)
			continue
		}
		e.usrGroups[g.Name] = g
	}
	for i := range p.Devices {
		d := &p.Devices[i]
		if d.Name == "" {
			add("devices[%d]: nome obrigatório", i)
		}
		pfx, err := parsePrefix(d.Address)
		if err != nil {
			add("device %q: endereço inválido %q", d.Name, d.Address)
		}
		if d.Group != "" && e.devGroups[d.Group] == nil {
			add("device %q: grupo inexistente %q", d.Name, d.Group)
		}
		if d.MFA == "" {
			d.MFA = MFAInherit
		}
		if !validMode(d.MFA, true) {
			add("device %q: mfa inválido %q", d.Name, d.MFA)
		}
		if d.CodeEntry == "" {
			d.CodeEntry = EntryPrompt
		}
		if d.CodeEntry != EntryPrompt && d.CodeEntry != EntryAppend {
			add("device %q: code_entry inválido %q", d.Name, d.CodeEntry)
		}
		if len(d.Secret) < 16 {
			add("device %q: a chave compartilhada precisa de pelo menos 16 caracteres", d.Name)
		}
		e.devices = append(e.devices, compiledDevice{prefix: pfx, d: d})
	}
	for i := range p.Users {
		u := &p.Users[i]
		if u.Username == "" || e.users[u.Username] != nil {
			add("users[%d]: username vazio ou repetido", i)
			continue
		}
		if !passhash.Valid(u.PasswordHash) {
			add("user %q: password_hash precisa ser Argon2id", u.Username)
		}
		if u.TOTPSecret != "" {
			if _, err := totp.CodeAt(u.TOTPSecret, 0); err != nil {
				add("user %q: totp_secret inválido", u.Username)
			}
		}
		cu := &compiledUser{u: u, groups: map[string]bool{}}
		for _, g := range u.Groups {
			if e.usrGroups[g] == nil {
				add("user %q: grupo inexistente %q", u.Username, g)
			}
			cu.groups[g] = true
		}
		for _, s := range u.AllowedSources {
			pfx, err := parsePrefix(s)
			if err != nil {
				add("user %q: origem inválida %q", u.Username, s)
				continue
			}
			cu.sources = append(cu.sources, pfx)
		}
		if u.Service {
			if len(cu.sources) == 0 {
				add("user %q: conta de serviço precisa de allowed_sources", u.Username)
			}
			if u.TOTPSecret != "" {
				add("user %q: conta de serviço não usa TOTP", u.Username)
			}
		}
		e.users[u.Username] = cu
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Action != Allow && r.Action != Deny {
			add("rule %q: action deve ser allow ou deny", r.Name)
		}
		if r.PrivLevel < 0 || r.PrivLevel > 15 {
			add("rule %q: priv_level entre 0 e 15", r.Name)
		}
		cr := compiledRule{r: r, users: set(r.UserGroups), devices: set(r.DeviceGroups)}
		for g := range cr.users {
			if e.usrGroups[g] == nil {
				add("rule %q: grupo de técnicos inexistente %q", r.Name, g)
			}
		}
		for g := range cr.devices {
			if e.devGroups[g] == nil {
				add("rule %q: grupo de equipamentos inexistente %q", r.Name, g)
			}
		}
		m, err := compileCommands(r.Commands)
		if err != nil {
			add("rule %q: padrão de comando inválido: %v", r.Name, err)
		}
		cr.commands = m
		e.rules = append(e.rules, cr)
	}
	if len(errs) > 0 {
		return nil, errors.New("política inválida:\n  - " + strings.Join(errs, "\n  - "))
	}
	return e, nil
}

func validMode(m MFAMode, allowInherit bool) bool {
	return m == MFAOff || m == MFATOTP || (allowInherit && m == MFAInherit)
}

func set(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Version devolve a versão da política.
func (e *Engine) Version() int64 { return e.p.Version }

// Customer devolve os dados do cliente.
func (e *Engine) Customer() Customer { return e.p.Customer }

// DeviceFor encontra o equipamento pelo IP de origem. Com faixas sobrepostas vence a mais específica.
func (e *Engine) DeviceFor(ip netip.Addr) (*Device, bool) {
	ip = ip.Unmap()
	var best *compiledDevice
	for i := range e.devices {
		cd := &e.devices[i]
		if cd.prefix.Contains(ip) && (best == nil || cd.prefix.Bits() > best.prefix.Bits()) {
			best = cd
		}
	}
	if best == nil {
		return nil, false
	}
	return best.d, true
}

// User devolve o técnico pelo nome de usuário.
func (e *Engine) User(username string) (*User, bool) {
	cu, ok := e.users[username]
	if !ok {
		return nil, false
	}
	return cu.u, true
}

// SourceAllowed verifica a restrição de origem do usuário. remAddr vem do equipamento e
// pode não ser um IP (ex.: "tty0", console); nesse caso só passa se não houver restrição.
func (e *Engine) SourceAllowed(username, remAddr string) bool {
	cu, ok := e.users[username]
	if !ok {
		return false
	}
	if len(cu.sources) == 0 {
		return true
	}
	ip, ok := ParseRemoteAddr(remAddr)
	if !ok {
		return false
	}
	for _, p := range cu.sources {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseRemoteAddr extrai o IP do campo rem_addr do TACACS+ (aceita "ip", "ip:porta", "[ipv6]:porta").
func ParseRemoteAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// MatchRule devolve a primeira regra que corresponde ao técnico e ao equipamento.
func (e *Engine) MatchRule(username string, d *Device) (*Rule, bool) {
	cr, ok := e.matchRule(username, d)
	if !ok {
		return nil, false
	}
	return cr.r, true
}

func (e *Engine) matchRule(username string, d *Device) (*compiledRule, bool) {
	cu, ok := e.users[username]
	if !ok {
		return nil, false
	}
	for i := range e.rules {
		cr := &e.rules[i]
		if len(cr.devices) > 0 && !cr.devices[d.Group] {
			continue
		}
		if len(cr.users) > 0 && !intersects(cr.users, cu.groups) {
			continue
		}
		return cr, true
	}
	return nil, false
}

func intersects(a, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

// MFADecision é o MFA efetivo para um técnico num equipamento.
type MFADecision struct {
	Required    bool
	TrustWindow time.Duration
	Entry       CodeEntry
	// Reason explica de onde veio a decisão (mostrado no testador e na auditoria).
	Reason string
}

// MFAFor calcula o MFA efetivo: equipamento → grupo → cliente, endurecido pelas regras dos
// grupos de técnicos. O mais restritivo vence.
func (e *Engine) MFAFor(username string, d *Device) MFADecision {
	cu, ok := e.users[username]
	dec := MFADecision{Entry: d.CodeEntry}
	if !ok {
		return MFADecision{Required: true, Entry: d.CodeEntry, Reason: "usuário desconhecido"}
	}
	if cu.u.Service {
		return MFADecision{Entry: d.CodeEntry, Reason: "conta de serviço (restrita por origem)"}
	}

	mode, src := d.MFA, "equipamento "+d.Name
	window := d.TrustWindowSeconds
	g := e.devGroups[d.Group]
	if mode == MFAInherit {
		if g != nil && g.MFA != MFAInherit {
			mode, src = g.MFA, "grupo "+g.Name
		} else {
			mode, src = e.p.Customer.MFA, "cliente "+e.p.Customer.Code
		}
	}
	if window == nil && g != nil {
		window = g.TrustWindowSeconds
	}
	w := e.p.Customer.TrustWindowSeconds
	if window != nil {
		w = *window
	}
	dec.Required = mode == MFATOTP
	dec.Reason = string(mode) + " definido em " + src

	for name := range cu.groups {
		ug := e.usrGroups[name]
		if ug == nil || !ug.RequireMFA {
			continue
		}
		if !dec.Required {
			dec.Required = true
			dec.Reason = "totp exigido pelo grupo de técnicos " + ug.Name
		}
		if ug.TrustWindowSeconds != nil && *ug.TrustWindowSeconds < w {
			w = *ug.TrustWindowSeconds
		}
	}
	if dec.Required {
		dec.TrustWindow = time.Duration(w) * time.Second
	}
	return dec
}

// Decision é o resultado de uma autorização.
type Decision struct {
	Allowed   bool
	Rule      string
	PrivLevel int
	Reason    string
}

// AuthorizeSession decide se o técnico pode abrir sessão no equipamento.
func (e *Engine) AuthorizeSession(username string, d *Device) Decision {
	cr, ok := e.matchRule(username, d)
	if !ok {
		return Decision{Reason: "nenhuma regra corresponde"}
	}
	if cr.r.Action != Allow {
		return Decision{Rule: cr.r.Name, Reason: "regra nega acesso"}
	}
	return Decision{Allowed: true, Rule: cr.r.Name, PrivLevel: cr.r.PrivLevel, Reason: "regra permite acesso"}
}

// AuthorizeCommand decide se o técnico pode executar cmd no equipamento.
func (e *Engine) AuthorizeCommand(username string, d *Device, cmd string) Decision {
	cr, ok := e.matchRule(username, d)
	if !ok {
		return Decision{Reason: "nenhuma regra corresponde"}
	}
	if cr.r.Action != Allow {
		return Decision{Rule: cr.r.Name, Reason: "regra nega acesso"}
	}
	allowed, why := cr.commands.decide(cmd)
	return Decision{Allowed: allowed, Rule: cr.r.Name, PrivLevel: cr.r.PrivLevel, Reason: why}
}
