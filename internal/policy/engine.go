package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // o Edge roda em imagem mínima, sem base de fusos

	"github.com/ajcorrea/onegate/internal/passhash"
	"github.com/ajcorrea/onegate/internal/totp"
)

// DefaultTimezone é o fuso dos horários quando o cliente não define outro.
const DefaultTimezone = "America/Sao_Paulo"

// Engine é a política compilada e validada, pronta para decisões.
type Engine struct {
	p         *Policy
	loc       *time.Location
	devices   []compiledDevice
	devGroups map[string]*DeviceGroup
	usrGroups map[string]bool
	users     map[string]*compiledUser
	networks  map[string][]netip.Prefix
	profiles  map[string]*compiledProfile
	schedules map[string][]compiledWindow
	rules     []compiledRule
	warnings  []string
}

type compiledDevice struct {
	prefix netip.Prefix
	d      *Device
	groups map[string]bool
}

type compiledUser struct {
	u      *User
	groups map[string]bool
}

type compiledProfile struct {
	p        *Profile
	commands *commandMatcher
}

type compiledWindow struct {
	days       [8]bool // índice 1..7
	start, end int     // minutos desde 00:00
}

type compiledRule struct {
	r         *Rule
	num       int
	missing   []string
	whoAll    bool
	users     map[string]bool
	groups    map[string]bool
	whereAll  bool
	devices   map[string]bool
	devGroups map[string]bool
	vendors   map[string]bool
	fromAll   bool
	nets      []netip.Prefix
	profile   *compiledProfile // nil = nenhum comando
	always    bool
	windows   []compiledWindow
}

// Compile valida a política e prepara as estruturas de decisão.
// Regras incompletas não impedem a carga: viram avisos e nunca correspondem.
func Compile(p *Policy) (*Engine, error) {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	e := &Engine{
		p:         p,
		devGroups: map[string]*DeviceGroup{},
		usrGroups: map[string]bool{},
		users:     map[string]*compiledUser{},
		networks:  map[string][]netip.Prefix{},
		profiles:  map[string]*compiledProfile{},
		schedules: map[string][]compiledWindow{},
	}
	if p.Format != FormatVersion {
		add("format deve ser %d (recebido %d)", FormatVersion, p.Format)
	}
	if p.Customer.Code == "" {
		add("customer.code é obrigatório")
	}
	if !validDomain(p.Customer.Domain) {
		add("customer.domain inválido %q", p.Customer.Domain)
	}
	if !validDomain(p.GlobalDomain) {
		add("global_domain inválido %q", p.GlobalDomain)
	}
	if p.Customer.MFA != MFAOff && p.Customer.MFA != MFATOTP {
		add("customer.mfa deve ser \"off\" ou \"totp\"")
	}
	if p.Customer.TrustWindowSeconds < 0 {
		add("customer.trust_window_seconds não pode ser negativo")
	}
	tz := p.Customer.Timezone
	if tz == "" {
		tz = DefaultTimezone
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		add("customer.timezone inválido %q", tz)
		loc = time.UTC
	}
	e.loc = loc

	for i := range p.DeviceGroups {
		g := &p.DeviceGroups[i]
		if g.Name == "" || e.devGroups[g.Name] != nil {
			add("device_groups[%d]: nome vazio ou repetido", i)
			continue
		}
		if g.MFA == "" {
			g.MFA = MFAInherit
		}
		if !validMode(g.MFA, true) {
			add("device_groups %q: mfa inválido %q", g.Name, g.MFA)
		}
		if g.TrustWindowSeconds != nil && *g.TrustWindowSeconds < 0 {
			add("device_groups %q: janela negativa", g.Name)
		}
		e.devGroups[g.Name] = g
	}
	devNames := map[string]bool{}
	for i := range p.Devices {
		d := &p.Devices[i]
		if d.Name == "" || devNames[d.Name] {
			add("devices[%d]: nome vazio ou repetido", i)
		}
		devNames[d.Name] = true
		pfx, err := parsePrefix(d.Address)
		if err != nil {
			add("device %q: endereço inválido %q", d.Name, d.Address)
		}
		for _, g := range d.Groups {
			if e.devGroups[g] == nil {
				add("device %q: grupo inexistente %q", d.Name, g)
			}
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
		e.devices = append(e.devices, compiledDevice{prefix: pfx, d: d, groups: set(d.Groups)})
	}
	for i := range p.UserGroups {
		g := p.UserGroups[i].Name
		if _, _, ok := splitAt(g); !ok || e.usrGroups[g] {
			add("user_groups[%d]: nome vazio, sem domínio ou repetido %q", i, g)
			continue
		}
		e.usrGroups[g] = true
	}
	for i := range p.Users {
		u := &p.Users[i]
		u.Username = strings.ToLower(strings.TrimSpace(u.Username))
		if _, _, ok := splitAt(u.Username); !ok || e.users[u.Username] != nil {
			add("users[%d]: username vazio, sem domínio ou repetido %q", i, u.Username)
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
			if !e.usrGroups[g] {
				add("user %q: grupo inexistente %q", u.Username, g)
			}
			cu.groups[g] = true
		}
		e.users[u.Username] = cu
	}
	for i := range p.Networks {
		n := &p.Networks[i]
		if n.Name == "" || e.networks[n.Name] != nil {
			add("networks[%d]: nome vazio ou repetido", i)
			continue
		}
		if len(n.CIDRs) == 0 {
			add("network %q: sem faixas", n.Name)
		}
		var ps []netip.Prefix
		for _, c := range n.CIDRs {
			pfx, err := parsePrefix(c)
			if err != nil {
				add("network %q: faixa inválida %q", n.Name, c)
				continue
			}
			ps = append(ps, pfx)
		}
		e.networks[n.Name] = ps
	}
	for i := range p.Profiles {
		pr := &p.Profiles[i]
		if pr.Name == "" || e.profiles[pr.Name] != nil {
			add("profiles[%d]: nome vazio ou repetido", i)
			continue
		}
		if pr.PrivLevel < 0 || pr.PrivLevel > 15 {
			add("profile %q: priv_level entre 0 e 15", pr.Name)
		}
		m, err := compileCommands(pr.Commands)
		if err != nil {
			add("profile %q: padrão de comando inválido: %v", pr.Name, err)
		}
		e.profiles[pr.Name] = &compiledProfile{p: pr, commands: m}
	}
	for i := range p.Schedules {
		s := &p.Schedules[i]
		if s.Name == "" || e.schedules[s.Name] != nil {
			add("schedules[%d]: nome vazio ou repetido", i)
			continue
		}
		if len(s.Windows) == 0 {
			add("schedule %q: sem janelas", s.Name)
		}
		var ws []compiledWindow
		for j, w := range s.Windows {
			cw, err := compileWindow(w)
			if err != nil {
				add("schedule %q janela %d: %v", s.Name, j+1, err)
				continue
			}
			ws = append(ws, cw)
		}
		e.schedules[s.Name] = ws
	}

	seenCustomer := false
	for i := range p.Rules {
		r := &p.Rules[i]
		label := fmt.Sprintf("regra #%d %q", i+1, r.Name)
		if r.Name == "" {
			add("regra #%d: nome obrigatório", i+1)
		}
		switch r.Scope {
		case ScopeGlobal:
			if seenCustomer {
				add("%s: regras globais precisam vir antes das do cliente", label)
			}
		case ScopeCustomer:
			seenCustomer = true
		default:
			add("%s: scope deve ser global ou customer", label)
		}
		if r.Action != Allow && r.Action != Deny {
			add("%s: action deve ser allow ou deny", label)
		}
		cr := compiledRule{r: r, num: i + 1, missing: r.Missing(),
			users: map[string]bool{}, groups: map[string]bool{},
			devices: map[string]bool{}, devGroups: map[string]bool{}, vendors: map[string]bool{}}
		if len(cr.missing) > 0 {
			e.warnings = append(e.warnings, fmt.Sprintf("%s incompleta (sem %s): ignorada", label, strings.Join(cr.missing, ", ")))
		}
		for _, ref := range r.Who {
			kind, val := splitRef(ref)
			switch {
			case ref == RefAll:
				cr.whoAll = true
			case ref == RefNone:
			case kind == "user":
				val = strings.ToLower(val)
				if e.users[val] == nil {
					// Usuário desativado ou removido some da política; a regra continua válida.
					e.warnings = append(e.warnings, fmt.Sprintf("%s: usuário %q não está nesta política", label, val))
				}
				cr.users[val] = true
			case kind == "group":
				if !e.usrGroups[val] {
					add("%s: grupo de técnicos inexistente %q", label, val)
				}
				cr.groups[val] = true
			default:
				add("%s: Quem inválido %q", label, ref)
			}
		}
		for _, ref := range r.Where {
			kind, val := splitRef(ref)
			switch {
			case ref == RefAll:
				cr.whereAll = true
			case ref == RefNone:
			case kind == "device":
				if !devNames[val] {
					add("%s: equipamento inexistente %q", label, val)
				}
				cr.devices[val] = true
			case kind == "group":
				if e.devGroups[val] == nil {
					add("%s: grupo de equipamentos inexistente %q", label, val)
				}
				cr.devGroups[val] = true
			case kind == "vendor" && val != "":
				cr.vendors[strings.ToLower(val)] = true
			default:
				add("%s: Onde inválido %q", label, ref)
			}
		}
		for _, ref := range r.From {
			kind, val := splitRef(ref)
			switch {
			case ref == RefAll:
				cr.fromAll = true
			case ref == RefNone:
			case kind == "net":
				ps, ok := e.networks[val]
				if !ok {
					add("%s: objeto de IP inexistente %q", label, val)
				}
				cr.nets = append(cr.nets, ps...)
			case kind == "cidr":
				pfx, err := parsePrefix(val)
				if err != nil {
					add("%s: faixa inválida %q", label, val)
				}
				cr.nets = append(cr.nets, pfx)
			default:
				add("%s: De onde inválido %q", label, ref)
			}
		}
		if kind, val := splitRef(r.What); r.What != "" && r.What != RefNone {
			if kind != "profile" || e.profiles[val] == nil {
				add("%s: perfil de comandos inexistente %q", label, r.What)
			} else {
				cr.profile = e.profiles[val]
			}
		}
		if len(r.When) == 0 {
			cr.always = true
		}
		for _, ref := range r.When {
			kind, val := splitRef(ref)
			switch {
			case ref == RefAlways:
				cr.always = true
			case ref == RefNever:
			case kind == "schedule":
				ws, ok := e.schedules[val]
				if !ok {
					add("%s: horário inexistente %q", label, val)
				}
				cr.windows = append(cr.windows, ws...)
			default:
				add("%s: Quando inválido %q", label, ref)
			}
		}
		switch r.MFA {
		case "", RuleMFADevice, RuleMFATOTP, RuleMFANone:
		default:
			add("%s: MFA inválido %q", label, r.MFA)
		}
		e.rules = append(e.rules, cr)
	}
	if len(errs) > 0 {
		return nil, errors.New("política inválida:\n  - " + strings.Join(errs, "\n  - "))
	}
	return e, nil
}

func validDomain(d string) bool {
	return d != "" && strings.Contains(d, ".") && !strings.ContainsAny(d, "@ /")
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

func splitRef(ref string) (kind, val string) {
	k, v, ok := strings.Cut(ref, ":")
	if !ok {
		return "", ref
	}
	return k, v
}

// splitAt separa "nome@dominio".
func splitAt(s string) (local, domain string, ok bool) {
	i := strings.LastIndexByte(s, '@')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
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
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func parseClock(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
		return 0, fmt.Errorf("hora inválida %q (use HH:MM)", s)
	}
	return hh*60 + mm, nil
}

func compileWindow(w Window) (compiledWindow, error) {
	var cw compiledWindow
	if len(w.Days) == 0 {
		return cw, errors.New("sem dias")
	}
	for _, d := range w.Days {
		if d < 1 || d > 7 {
			return cw, fmt.Errorf("dia inválido %d (1 = segunda … 7 = domingo)", d)
		}
		cw.days[d] = true
	}
	var err error
	if cw.start, err = parseClock(w.Start); err != nil {
		return cw, err
	}
	if cw.end, err = parseClock(w.End); err != nil {
		return cw, err
	}
	return cw, nil
}

func isoDay(t time.Time) int {
	d := int(t.Weekday())
	if d == 0 {
		return 7
	}
	return d
}

func (w compiledWindow) contains(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	d := isoDay(t)
	if w.start < w.end {
		return w.days[d] && m >= w.start && m < w.end
	}
	// atravessa a meia-noite: parte da noite do dia d, ou madrugada depois do dia anterior
	prev := d - 1
	if prev == 0 {
		prev = 7
	}
	return (w.days[d] && m >= w.start) || (w.days[prev] && m < w.end)
}

// Version devolve a versão da política.
func (e *Engine) Version() int64 { return e.p.Version }

// Customer devolve os dados do cliente.
func (e *Engine) Customer() Customer { return e.p.Customer }

// Warnings lista avisos da compilação (regras incompletas, usuários fora da política).
func (e *Engine) Warnings() []string { return append([]string(nil), e.warnings...) }

// Location devolve o fuso usado nos horários.
func (e *Engine) Location() *time.Location { return e.loc }

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

// DeviceByName encontra o equipamento pelo nome (usado pelo simulador).
func (e *Engine) DeviceByName(name string) (*Device, bool) {
	for i := range e.devices {
		if e.devices[i].d.Name == name {
			return e.devices[i].d, true
		}
	}
	return nil, false
}

func (e *Engine) compiledDevice(d *Device) *compiledDevice {
	for i := range e.devices {
		if e.devices[i].d == d {
			return &e.devices[i]
		}
	}
	return &compiledDevice{d: d, groups: set(d.Groups)}
}

// ResolveUser encontra o técnico pelo que foi digitado no equipamento. Sem "@", tenta o domínio
// do cliente e depois o domínio global. Não diferencia maiúsculas.
func (e *Engine) ResolveUser(typed string) (*User, bool) {
	n := strings.ToLower(strings.TrimSpace(typed))
	if n == "" {
		return nil, false
	}
	if strings.Contains(n, "@") {
		cu, ok := e.users[n]
		if !ok {
			return nil, false
		}
		return cu.u, true
	}
	for _, dom := range []string{e.p.Customer.Domain, e.p.GlobalDomain} {
		if cu, ok := e.users[n+"@"+dom]; ok {
			return cu.u, true
		}
	}
	return nil, false
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

// Request é o contexto de uma decisão.
type Request struct {
	// User é o que o técnico digitou (com ou sem domínio).
	User   string
	Device *Device
	// Source é o rem_addr informado pelo equipamento (IP do técnico, ou "tty0" no console).
	Source string
	Time   time.Time
}

// Step é uma linha do rastro de avaliação, mostrada no simulador e na auditoria.
type Step struct {
	Num    int    `json:"num"`
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Scope  string `json:"scope"`
	Status string `json:"status"` // hit | miss | incomplete | skip
	Note   string `json:"note"`
}

// MFADecision é o MFA efetivo para um técnico num equipamento.
type MFADecision struct {
	Required    bool          `json:"required"`
	TrustWindow time.Duration `json:"trust_window"`
	Entry       CodeEntry     `json:"entry"`
	// Reason explica de onde veio a decisão.
	Reason string `json:"reason"`
}

// Result é o resultado de uma avaliação.
type Result struct {
	// Allowed: acesso (e, em AuthorizeCommand, o comando) permitido.
	Allowed   bool        `json:"allowed"`
	Username  string      `json:"username,omitempty"`
	Rule      string      `json:"rule,omitempty"`
	RuleNum   int         `json:"rule_num,omitempty"`
	Scope     string      `json:"scope,omitempty"`
	PrivLevel int         `json:"priv_level"`
	Profile   string      `json:"profile,omitempty"`
	MFA       MFADecision `json:"mfa"`
	Reason    string      `json:"reason"`
	Trail     []Step      `json:"trail"`
}

// Evaluate decide se o técnico pode entrar no equipamento: a primeira regra que corresponder
// decide; sem correspondência, nega.
func (e *Engine) Evaluate(req Request) Result {
	res := Result{}
	if req.Device == nil {
		res.Reason = "equipamento não cadastrado"
		return res
	}
	u, ok := e.ResolveUser(req.User)
	if !ok {
		res.Reason = "usuário desconhecido"
		return res
	}
	res.Username = u.Username
	if u.Disabled {
		res.Reason = "usuário desativado"
		return res
	}
	cu := e.users[u.Username]
	cd := e.compiledDevice(req.Device)
	src, srcOK := ParseRemoteAddr(req.Source)
	t := req.Time
	if t.IsZero() {
		t = time.Now()
	}
	t = t.In(e.loc)
	_, userDomain, _ := splitAt(u.Username)

	var hit *compiledRule
	for i := range e.rules {
		cr := &e.rules[i]
		st := Step{Num: cr.num, ID: cr.r.ID, Name: cr.r.Name, Scope: cr.r.Scope}
		if hit != nil {
			st.Status, st.Note = "skip", "não avaliada"
			res.Trail = append(res.Trail, st)
			continue
		}
		if note := e.miss(cr, cu, userDomain, cd, src, srcOK, req.Source, t); note != "" {
			st.Status, st.Note = "miss", note
			if len(cr.missing) > 0 {
				st.Status = "incomplete"
			}
			res.Trail = append(res.Trail, st)
			continue
		}
		st.Status, st.Note = "hit", "corresponde: decide"
		res.Trail = append(res.Trail, st)
		hit = cr
	}
	if hit == nil {
		res.Reason = "nenhuma regra corresponde: vale o padrão (negar)"
		return res
	}
	res.Rule, res.RuleNum, res.Scope = hit.r.Name, hit.num, hit.r.Scope
	if hit.r.Action == Deny {
		res.Reason = fmt.Sprintf("regra #%d %q nega o acesso", hit.num, hit.r.Name)
		return res
	}
	res.Allowed = true
	res.PrivLevel = 1
	res.Profile = "Nenhum comando"
	if hit.profile != nil {
		res.PrivLevel = hit.profile.p.PrivLevel
		res.Profile = hit.profile.p.Name
	}
	res.MFA = e.mfaFor(hit, req.Device)
	res.Reason = fmt.Sprintf("regra #%d %q permite (perfil %s)", hit.num, hit.r.Name, res.Profile)
	return res
}

// miss devolve por que a regra não corresponde, ou "" se corresponde.
func (e *Engine) miss(cr *compiledRule, cu *compiledUser, userDomain string, cd *compiledDevice,
	src netip.Addr, srcOK bool, rawSrc string, t time.Time) string {
	if len(cr.missing) > 0 {
		return "incompleta (sem " + strings.Join(cr.missing, ", ") + "): ignorada"
	}
	// Quem
	who := cr.users[cu.u.Username] || intersects(cr.groups, cu.groups)
	if cr.whoAll {
		// "Todos" numa regra do cliente vale só para usuários do domínio do cliente.
		who = who || cr.r.Scope == ScopeGlobal || userDomain == e.p.Customer.Domain
	}
	if !who {
		return "quem não corresponde"
	}
	// Onde
	where := cr.whereAll || cr.devices[cd.d.Name] || intersects(cr.devGroups, cd.groups) ||
		(cd.d.Vendor != "" && cr.vendors[strings.ToLower(cd.d.Vendor)])
	if !where {
		return "equipamento fora do Onde"
	}
	// De onde
	from := cr.fromAll
	if !from && srcOK {
		for _, p := range cr.nets {
			if p.Contains(src) {
				from = true
				break
			}
		}
	}
	if !from {
		if !srcOK {
			return fmt.Sprintf("origem %q não é um IP (só \"Qualquer IP\" aceita)", rawSrc)
		}
		return "origem " + src.String() + " fora das faixas"
	}
	// Quando
	when := cr.always
	for _, w := range cr.windows {
		if when {
			break
		}
		when = w.contains(t)
	}
	if !when {
		if len(cr.windows) == 0 {
			return "quando = Nunca"
		}
		return "fora do horário (" + t.Format("Mon 15:04") + ")"
	}
	return ""
}

func intersects(a, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

// mfaFor calcula o MFA da regra. "device" segue equipamento → primeiro grupo → cliente.
func (e *Engine) mfaFor(cr *compiledRule, d *Device) MFADecision {
	dec := MFADecision{Entry: d.CodeEntry}
	mode, src := d.MFA, "equipamento "+d.Name
	var window *int = d.TrustWindowSeconds
	var g *DeviceGroup
	if len(d.Groups) > 0 {
		g = e.devGroups[d.Groups[0]]
	}
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
	switch cr.r.MFA {
	case RuleMFATOTP:
		dec.Required, dec.Reason = true, "TOTP obrigatório pela regra"
	case RuleMFANone:
		dec.Required, dec.Reason = false, "sem MFA pela regra"
	default:
		dec.Required = mode == MFATOTP
		dec.Reason = "segue o equipamento: " + string(mode) + " definido em " + src
	}
	if dec.Required {
		dec.TrustWindow = time.Duration(w) * time.Second
	}
	return dec
}

// AuthorizeCommand decide se o técnico pode executar cmd. A regra é reavaliada a cada comando,
// então sair do horário ou trocar a política vale na hora.
func (e *Engine) AuthorizeCommand(req Request, cmd string) Result {
	res := e.Evaluate(req)
	if !res.Allowed {
		return res
	}
	cr := &e.rules[res.RuleNum-1]
	if cr.profile == nil {
		res.Allowed = false
		res.Reason = fmt.Sprintf("regra #%d %q: perfil Nenhum comando", res.RuleNum, res.Rule)
		return res
	}
	ok, why := cr.profile.commands.decide(cmd)
	res.Allowed = ok
	res.Reason = fmt.Sprintf("regra #%d %q, perfil %s: %s", res.RuleNum, res.Rule, res.Profile, why)
	return res
}
