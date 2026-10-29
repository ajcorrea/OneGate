package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ajcorrea/onegate/internal/passhash"
	"github.com/ajcorrea/onegate/internal/policy"
)

// Regras AAA na nuvem.
//
// Objetos (grupos, redes, perfis, horários), equipamentos e técnicos valem na hora: entram no próximo
// documento gerado para o Edge. As regras têm rascunho e publicação: o Edge só recebe a última versão
// publicada das regras globais e das regras do cliente.

// Tipos de objeto AAA.
const (
	kindUserGroup   = "user_group"
	kindDeviceGroup = "device_group"
	kindNetwork     = "network"
	kindProfile     = "profile"
	kindSchedule    = "schedule"
)

var objectKinds = map[string]string{
	kindUserGroup:   "Grupo de técnicos",
	kindDeviceGroup: "Grupo de equipamentos",
	kindNetwork:     "Rede (IP de origem)",
	kindProfile:     "Perfil de comandos",
	kindSchedule:    "Horário",
}

// AAAObject é um objeto global (CustomerID nulo) ou de um cliente.
type AAAObject struct {
	ID          string          `json:"id"`
	CustomerID  *string         `json:"customer_id"`
	Kind        string          `json:"kind"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Data        json.RawMessage `json:"data"`
	Members     []string        `json:"members,omitempty"` // grupo de técnicos: IDs das pessoas
}

type deviceGroupData struct {
	MFA                string `json:"mfa"`
	TrustWindowSeconds *int   `json:"trust_window_seconds,omitempty"`
}

type networkData struct {
	CIDRs []string `json:"cidrs"`
}

type profileData struct {
	PrivLevel int      `json:"priv_level"`
	Default   string   `json:"default,omitempty"`
	Allow     []string `json:"allow,omitempty"`
	Deny      []string `json:"deny,omitempty"`
}

type scheduleData struct {
	Windows []policy.Window `json:"windows"`
}

func strictDecode(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return validationError("Dados do objeto inválidos.")
	}
	return nil
}

func cleanList(xs []string) []string {
	out := []string{}
	for _, x := range xs {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// normalizeObjectData valida o conteúdo do objeto conforme o tipo e devolve a forma canônica.
func normalizeObjectData(kind string, raw json.RawMessage) (json.RawMessage, error) {
	var v any
	switch kind {
	case kindUserGroup:
		var d struct{}
		if err := strictDecode(raw, &d); err != nil {
			return nil, err
		}
		v = d
	case kindDeviceGroup:
		var d deviceGroupData
		if err := strictDecode(raw, &d); err != nil {
			return nil, err
		}
		if d.MFA == "" {
			d.MFA = "inherit"
		}
		if d.MFA != "inherit" && d.MFA != "off" && d.MFA != "totp" {
			return nil, validationError("MFA do grupo: herdar, desligado ou TOTP.")
		}
		if d.TrustWindowSeconds != nil && (*d.TrustWindowSeconds < 0 || *d.TrustWindowSeconds > 86400) {
			return nil, validationError("Janela de confiança entre 0 e 24 horas.")
		}
		v = d
	case kindNetwork:
		var d networkData
		if err := strictDecode(raw, &d); err != nil {
			return nil, err
		}
		d.CIDRs = cleanList(d.CIDRs)
		if len(d.CIDRs) == 0 {
			return nil, validationError("Informe pelo menos uma faixa de IP.")
		}
		for i, c := range d.CIDRs {
			n, err := policy.NormalizeCIDR(c)
			if err != nil {
				return nil, validationError("Faixa inválida: " + c)
			}
			d.CIDRs[i] = n
		}
		v = d
	case kindProfile:
		var d profileData
		if err := strictDecode(raw, &d); err != nil {
			return nil, err
		}
		d.Allow, d.Deny = cleanList(d.Allow), cleanList(d.Deny)
		if err := policy.ValidateProfile(policy.Profile{Name: "x", PrivLevel: d.PrivLevel,
			Commands: policy.CommandPolicy{Default: policy.Action(d.Default), Allow: d.Allow, Deny: d.Deny}}); err != nil {
			return nil, validationError("Perfil: " + err.Error() + ".")
		}
		v = d
	case kindSchedule:
		var d scheduleData
		if err := strictDecode(raw, &d); err != nil {
			return nil, err
		}
		if err := policy.ValidateSchedule(policy.Schedule{Name: "x", Windows: d.Windows}); err != nil {
			return nil, validationError("Horário: " + err.Error() + ".")
		}
		v = d
	default:
		return nil, validationError("Tipo de objeto inválido.")
	}
	b, err := json.Marshal(v)
	return b, err
}

func scopeKey(cid *string) string {
	if cid == nil {
		return ""
	}
	return *cid
}

// loadObjects devolve os objetos globais e, se cid != "", os do cliente.
func loadObjects(ctx context.Context, tx pgx.Tx, cid string) ([]*AAAObject, error) {
	q := `SELECT id::text, customer_id::text, kind, name, description, data FROM aaa_objects WHERE customer_id IS NULL`
	args := []any{}
	if cid != "" {
		q += ` OR customer_id = $1`
		args = append(args, cid)
	}
	rows, err := tx.Query(ctx, q+` ORDER BY kind, lower(name)`, args...)
	if err != nil {
		return nil, err
	}
	var out []*AAAObject
	byID := map[string]*AAAObject{}
	for rows.Next() {
		o := &AAAObject{}
		if err := rows.Scan(&o.ID, &o.CustomerID, &o.Kind, &o.Name, &o.Description, &o.Data); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, o)
		byID[o.ID] = o
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	mrows, err := tx.Query(ctx, `SELECT group_id::text, person_id::text FROM aaa_user_group_members ORDER BY person_id`)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var g, p string
		if err := mrows.Scan(&g, &p); err != nil {
			return nil, err
		}
		if o := byID[g]; o != nil {
			o.Members = append(o.Members, p)
		}
	}
	return out, mrows.Err()
}

// AAARule é uma regra no banco. As referências usam IDs:
// Who "user:<pessoa>" | "group:<objeto>"; Where "device:<equip>" | "group:<objeto>" | "vendor:<nome>";
// From "net:<objeto>" | "cidr:<faixa>"; What "profile:<objeto>"; When "schedule:<objeto>";
// além dos pré-definidos all, none, always e never.
type AAARule struct {
	ID         string   `json:"id"`
	CustomerID *string  `json:"customer_id"`
	Name       string   `json:"name"`
	Action     string   `json:"action"`
	Who        []string `json:"who"`
	Where      []string `json:"where"`
	From       []string `json:"from"`
	What       string   `json:"what"`
	When       []string `json:"when"`
	MFA        string   `json:"mfa"`
}

func (r *AAARule) missing() []string {
	pr := policy.Rule{Action: policy.Action(r.Action), Who: r.Who, Where: r.Where, From: r.From, What: r.What}
	return pr.Missing()
}

func loadRules(ctx context.Context, tx pgx.Tx, cid string) ([]AAARule, error) {
	q := `SELECT id::text, customer_id::text, name, action, who, where_refs, from_refs, what, when_refs, mfa FROM aaa_rules WHERE `
	args := []any{}
	if cid == "" {
		q += `customer_id IS NULL`
	} else {
		q += `customer_id = $1`
		args = append(args, cid)
	}
	rows, err := tx.Query(ctx, q+` ORDER BY position`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AAARule{}
	for rows.Next() {
		var r AAARule
		if err := rows.Scan(&r.ID, &r.CustomerID, &r.Name, &r.Action, &r.Who, &r.Where, &r.From, &r.What, &r.When, &r.MFA); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Publication é uma versão publicada das regras de um escopo.
type Publication struct {
	Version     int       `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	PublishedBy string    `json:"published_by"`
	Note        string    `json:"note"`
	Rules       []AAARule `json:"-"`
}

func loadPublication(ctx context.Context, tx pgx.Tx, cid string) (*Publication, error) {
	q := `SELECT p.version, p.published_at, coalesce(pe.name, 'sistema'), p.note, p.snapshot
	        FROM aaa_publications p LEFT JOIN people pe ON pe.id = p.published_by WHERE `
	args := []any{}
	if cid == "" {
		q += `p.customer_id IS NULL`
	} else {
		q += `p.customer_id = $1`
		args = append(args, cid)
	}
	var pub Publication
	var snap []byte
	err := tx.QueryRow(ctx, q+` ORDER BY p.version DESC LIMIT 1`, args...).Scan(&pub.Version, &pub.PublishedAt, &pub.PublishedBy, &pub.Note, &snap)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s struct {
		Rules []AAARule `json:"rules"`
	}
	if err := json.Unmarshal(snap, &s); err != nil {
		return nil, err
	}
	pub.Rules = s.Rules
	return &pub, nil
}

// aaaDevice é um equipamento cadastrado.
type aaaDevice struct {
	ID                 string    `json:"id"`
	CustomerID         string    `json:"customer_id"`
	Name               string    `json:"name"`
	Address            string    `json:"address"`
	Vendor             string    `json:"vendor"`
	Model              string    `json:"model"`
	MFA                string    `json:"mfa"`
	CodeEntry          string    `json:"code_entry"`
	TrustWindowSeconds *int      `json:"trust_window_seconds"`
	GroupIDs           []string  `json:"group_ids"`
	Active             bool      `json:"active"`
	UpdatedAt          time.Time `json:"updated_at"`
	secret             string
}

func loadDevices(ctx context.Context, tx pgx.Tx, cid, onlyID string) ([]*aaaDevice, error) {
	q := `SELECT d.id::text, d.customer_id::text, d.name, host(d.address) || CASE WHEN masklen(d.address) IN (32, 128) THEN '' ELSE '/' || masklen(d.address) END,
	             d.vendor, d.model, d.mfa, d.code_entry, d.trust_window_seconds, d.active, d.updated_at, d.secret,
	             coalesce(array_agg(m.group_id::text ORDER BY m.position) FILTER (WHERE m.group_id IS NOT NULL), '{}')
	        FROM aaa_devices d LEFT JOIN aaa_device_group_members m ON m.device_id = d.id
	       WHERE d.customer_id = $1 AND ($2 = '' OR d.id::text = $2)
	       GROUP BY d.id ORDER BY lower(d.name)`
	rows, err := tx.Query(ctx, q, cid, onlyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*aaaDevice
	for rows.Next() {
		d := &aaaDevice{}
		if err := rows.Scan(&d.ID, &d.CustomerID, &d.Name, &d.Address, &d.Vendor, &d.Model, &d.MFA, &d.CodeEntry,
			&d.TrustWindowSeconds, &d.Active, &d.UpdatedAt, &d.secret, &d.GroupIDs); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// technician é uma pessoa com acesso aos equipamentos.
type technician struct {
	PersonID   string
	CustomerID *string
	Name       string
	Username   string
	Hash       string
	TOTPSealed *string
}

func loadTechnicians(ctx context.Context, tx pgx.Tx, cid string) ([]technician, error) {
	rows, err := tx.Query(ctx, `
		SELECT p.id::text, p.customer_id::text, p.name, d.username, d.password_hash, d.totp_secret
		  FROM people p JOIN device_accounts d ON d.person_id = p.id
		 WHERE p.active AND d.active AND (p.customer_id IS NULL OR p.customer_id = $1)
		 ORDER BY d.username`, cid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []technician
	for rows.Next() {
		var t technician
		if err := rows.Scan(&t.PersonID, &t.CustomerID, &t.Name, &t.Username, &t.Hash, &t.TOTPSealed); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// buildMode define o que entra no documento.
type buildMode struct {
	Draft    bool // regras do rascunho (simulador) em vez das publicadas
	Simulate bool // sem segredos: chaves, hashes e TOTP de mentira
}

var (
	simHashOnce sync.Once
	simHash     string
)

// simulationHash é um hash Argon2id válido de uma senha aleatória, usado no simulador para não
// carregar hashes reais.
func simulationHash() string {
	simHashOnce.Do(func() {
		tok, _ := newToken()
		simHash, _ = passhash.Hash(tok)
	})
	return simHash
}

// builtPolicy é o documento gerado e o que foi descartado no caminho.
type builtPolicy struct {
	Policy   *policy.Policy
	Dropped  []string // referências a objetos, equipamentos ou pessoas que não existem mais
	Global   *Publication
	Customer *Publication
}

// buildPolicy gera o documento do Edge de um cliente.
func (s *Server) buildPolicy(ctx context.Context, tx pgx.Tx, cid string, mode buildMode) (*builtPolicy, error) {
	var code, name, domain, mfa, tz string
	var window int
	if err := tx.QueryRow(ctx, `SELECT code, name, domain, mfa, trust_window_seconds, timezone FROM customers WHERE id = $1`, cid).
		Scan(&code, &name, &domain, &mfa, &window, &tz); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	out := &builtPolicy{}
	gdom := GlobalDomain
	p := &policy.Policy{
		Format:       policy.FormatVersion,
		Version:      time.Now().UnixMilli(),
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		GlobalDomain: gdom,
		Customer: policy.Customer{Code: code, Name: name, Domain: domain, MFA: policy.MFAMode(mfa),
			TrustWindowSeconds: window, Timezone: tz},
		DeviceGroups: []policy.DeviceGroup{}, Devices: []policy.Device{}, UserGroups: []policy.UserGroup{},
		Users: []policy.User{}, Networks: []policy.Network{}, Profiles: []policy.Profile{}, Schedules: []policy.Schedule{},
		Rules: []policy.Rule{},
	}
	out.Policy = p

	// Regras: publicadas (Edge) ou rascunho (simulador).
	var gRules, cRules []AAARule
	if mode.Draft {
		if gRules, err = loadRules(ctx, tx, ""); err != nil {
			return nil, err
		}
		if cRules, err = loadRules(ctx, tx, cid); err != nil {
			return nil, err
		}
	} else {
		if out.Global, err = loadPublication(ctx, tx, ""); err != nil {
			return nil, err
		}
		if out.Customer, err = loadPublication(ctx, tx, cid); err != nil {
			return nil, err
		}
		if out.Global != nil {
			gRules, p.GlobalRulesVersion = out.Global.Rules, out.Global.Version
		}
		if out.Customer != nil {
			cRules, p.CustomerRulesVersion = out.Customer.Rules, out.Customer.Version
		}
	}

	objs, err := loadObjects(ctx, tx, cid)
	if err != nil {
		return nil, err
	}
	obj := map[string]*AAAObject{}
	for _, o := range objs {
		obj[o.ID] = o
		switch o.Kind {
		case kindUserGroup:
			dom := gdom
			if o.CustomerID != nil {
				dom = domain
			}
			p.UserGroups = append(p.UserGroups, policy.UserGroup{Name: o.Name + "@" + dom})
		case kindDeviceGroup:
			var d deviceGroupData
			_ = json.Unmarshal(o.Data, &d)
			p.DeviceGroups = append(p.DeviceGroups, policy.DeviceGroup{Name: o.Name, MFA: policy.MFAMode(d.MFA), TrustWindowSeconds: d.TrustWindowSeconds})
		case kindNetwork:
			var d networkData
			_ = json.Unmarshal(o.Data, &d)
			p.Networks = append(p.Networks, policy.Network{Name: o.Name, CIDRs: d.CIDRs})
		case kindProfile:
			var d profileData
			_ = json.Unmarshal(o.Data, &d)
			p.Profiles = append(p.Profiles, policy.Profile{Name: o.Name, PrivLevel: d.PrivLevel,
				Commands: policy.CommandPolicy{Default: policy.Action(d.Default), Allow: d.Allow, Deny: d.Deny}})
		case kindSchedule:
			var d scheduleData
			_ = json.Unmarshal(o.Data, &d)
			p.Schedules = append(p.Schedules, policy.Schedule{Name: o.Name, Windows: d.Windows})
		}
	}
	userGroupName := func(id string) (string, bool) {
		o := obj[id]
		if o == nil || o.Kind != kindUserGroup {
			return "", false
		}
		if o.CustomerID != nil {
			return o.Name + "@" + domain, true
		}
		return o.Name + "@" + gdom, true
	}

	devs, err := loadDevices(ctx, tx, cid, "")
	if err != nil {
		return nil, err
	}
	devName := map[string]string{}
	for _, d := range devs {
		if !d.Active {
			continue
		}
		devName[d.ID] = d.Name
		pd := policy.Device{Name: d.Name, Address: d.Address, Vendor: d.Vendor, MFA: policy.MFAMode(d.MFA),
			CodeEntry: policy.CodeEntry(d.CodeEntry), TrustWindowSeconds: d.TrustWindowSeconds}
		for _, g := range d.GroupIDs {
			if o := obj[g]; o != nil && o.Kind == kindDeviceGroup {
				pd.Groups = append(pd.Groups, o.Name)
			}
		}
		if mode.Simulate {
			pd.Secret = "simulacao-sem-chave-real"
		} else {
			if pd.Secret, err = s.Box.Open(d.secret, deviceSecretCtx(d.ID)); err != nil {
				return nil, fmt.Errorf("chave do equipamento %s: %w", d.Name, err)
			}
		}
		p.Devices = append(p.Devices, pd)
	}

	// Técnicos: os do cliente e, dos globais, só os que alguma regra global alcança.
	techs, err := loadTechnicians(ctx, tx, cid)
	if err != nil {
		return nil, err
	}
	globalAll := false
	globalUsers, globalGroups := map[string]bool{}, map[string]bool{}
	for _, r := range gRules {
		for _, ref := range r.Who {
			kind, val := splitRef(ref)
			switch {
			case ref == policy.RefAll:
				globalAll = true
			case kind == "user":
				globalUsers[val] = true
			case kind == "group":
				globalGroups[val] = true
			}
		}
	}
	memberOf := map[string][]string{}
	for _, o := range objs {
		if o.Kind == kindUserGroup {
			for _, m := range o.Members {
				memberOf[m] = append(memberOf[m], o.ID)
			}
		}
	}
	username := map[string]string{}
	for _, t := range techs {
		if t.CustomerID == nil && !globalAll && !globalUsers[t.PersonID] {
			reach := false
			for _, g := range memberOf[t.PersonID] {
				reach = reach || globalGroups[g]
			}
			if !reach {
				continue
			}
		}
		u := policy.User{Username: t.Username, Name: t.Name}
		for _, g := range memberOf[t.PersonID] {
			// O técnico só entra em grupos do próprio domínio.
			if o := obj[g]; o != nil && scopeKey(o.CustomerID) == scopeKey(t.CustomerID) {
				n, _ := userGroupName(g)
				u.Groups = append(u.Groups, n)
			}
		}
		if mode.Simulate {
			u.PasswordHash = simulationHash()
		} else {
			u.PasswordHash = t.Hash
			if t.TOTPSealed != nil {
				if u.TOTPSecret, err = s.Box.Open(*t.TOTPSealed, deviceCtx(t.PersonID)); err != nil {
					return nil, fmt.Errorf("TOTP de %s: %w", t.Username, err)
				}
			}
		}
		username[t.PersonID] = t.Username
		p.Users = append(p.Users, u)
	}

	// Regras: troca IDs por nomes. Referência a algo que não existe mais é descartada; se um campo
	// obrigatório ficar vazio, a regra fica incompleta e o Edge a ignora (nunca libera).
	translate := func(r AAARule, scope string) policy.Rule {
		pr := policy.Rule{ID: r.ID, Name: r.Name, Scope: scope, Action: policy.Action(r.Action), MFA: r.MFA,
			Who: []string{}, Where: []string{}, From: []string{}, When: []string{}}
		drop := func(ref string) {
			out.Dropped = append(out.Dropped, fmt.Sprintf("regra %q: %s não existe mais", r.Name, ref))
		}
		for _, ref := range r.Who {
			kind, val := splitRef(ref)
			switch {
			case ref == policy.RefAll || ref == policy.RefNone:
				pr.Who = append(pr.Who, ref)
			case kind == "user":
				if u, ok := username[val]; ok {
					pr.Who = append(pr.Who, "user:"+u)
				} // técnico sem acesso ativo: some sem aviso (é o esperado)
			case kind == "group":
				if n, ok := userGroupName(val); ok {
					pr.Who = append(pr.Who, "group:"+n)
				} else {
					drop("grupo de técnicos")
				}
			}
		}
		for _, ref := range r.Where {
			kind, val := splitRef(ref)
			switch {
			case ref == policy.RefAll || ref == policy.RefNone || kind == "vendor":
				pr.Where = append(pr.Where, ref)
			case kind == "device":
				if n, ok := devName[val]; ok {
					pr.Where = append(pr.Where, "device:"+n)
				}
			case kind == "group":
				if o := obj[val]; o != nil && o.Kind == kindDeviceGroup {
					pr.Where = append(pr.Where, "group:"+o.Name)
				} else {
					drop("grupo de equipamentos")
				}
			}
		}
		for _, ref := range r.From {
			kind, val := splitRef(ref)
			switch {
			case ref == policy.RefAll || ref == policy.RefNone || kind == "cidr":
				pr.From = append(pr.From, ref)
			case kind == "net":
				if o := obj[val]; o != nil && o.Kind == kindNetwork {
					pr.From = append(pr.From, "net:"+o.Name)
				} else {
					drop("rede")
				}
			}
		}
		if kind, val := splitRef(r.What); kind == "profile" {
			if o := obj[val]; o != nil && o.Kind == kindProfile {
				pr.What = "profile:" + o.Name
			} else {
				drop("perfil de comandos")
			}
		} else {
			pr.What = r.What
		}
		for _, ref := range r.When {
			kind, val := splitRef(ref)
			switch {
			case ref == policy.RefAlways || ref == policy.RefNever:
				pr.When = append(pr.When, ref)
			case kind == "schedule":
				if o := obj[val]; o != nil && o.Kind == kindSchedule {
					pr.When = append(pr.When, "schedule:"+o.Name)
				} else {
					// Horário apagado: a regra fica "Nunca", nunca "Sempre".
					pr.When = append(pr.When, policy.RefNever)
					drop("horário")
				}
			}
		}
		return pr
	}
	for _, r := range gRules {
		p.Rules = append(p.Rules, translate(r, policy.ScopeGlobal))
	}
	for _, r := range cRules {
		p.Rules = append(p.Rules, translate(r, policy.ScopeCustomer))
	}
	return out, nil
}

func splitRef(ref string) (string, string) {
	k, v, ok := strings.Cut(ref, ":")
	if !ok {
		return "", ref
	}
	return k, v
}

func deviceSecretCtx(id string) string { return "aaa-device:" + id }

// refIndex resolve referências em rótulos para a tela e valida o escopo das regras.
type refIndex struct {
	objects map[string]*AAAObject
	devices map[string]*aaaDevice
	people  map[string]refPerson
	domain  string
}

type refPerson struct {
	CustomerID *string
	Name       string
	Username   string // usuario@dominio (vazio se não tem acesso aos equipamentos)
}

// RefLabel é como uma referência aparece na tela.
type RefLabel struct {
	Label   string `json:"label"`
	Sub     string `json:"sub"`
	Kind    string `json:"kind"`
	Pre     bool   `json:"pre,omitempty"`     // objeto pré-definido
	Missing bool   `json:"missing,omitempty"` // não existe mais
}

var predefined = map[string]map[string]RefLabel{
	"who":   {"all": {Label: "Todos os usuários", Sub: "todos deste escopo", Pre: true}, "none": {Label: "Ninguém", Sub: "não corresponde a ninguém", Pre: true}},
	"where": {"all": {Label: "Todos os equipamentos", Sub: "todos deste escopo", Pre: true}, "none": {Label: "Nenhum equipamento", Sub: "não corresponde a nenhum", Pre: true}},
	"from":  {"all": {Label: "Qualquer IP", Sub: "0.0.0.0/0 e ::/0", Pre: true}, "none": {Label: "Nenhum IP", Sub: "bloqueia qualquer origem", Pre: true}},
	"what":  {"none": {Label: "Nenhum comando", Sub: "login sem poder executar nada", Pre: true}},
	"when":  {"always": {Label: "Sempre", Sub: "24×7", Pre: true}, "never": {Label: "Nunca", Sub: "regra desligada", Pre: true}},
}

func (s *Server) loadRefIndex(ctx context.Context, tx pgx.Tx, cid string) (*refIndex, error) {
	ix := &refIndex{objects: map[string]*AAAObject{}, devices: map[string]*aaaDevice{}, people: map[string]refPerson{}, domain: GlobalDomain}
	objs, err := loadObjects(ctx, tx, cid)
	if err != nil {
		return nil, err
	}
	for _, o := range objs {
		ix.objects[o.ID] = o
	}
	if cid != "" {
		devs, err := loadDevices(ctx, tx, cid, "")
		if err != nil {
			return nil, err
		}
		for _, d := range devs {
			ix.devices[d.ID] = d
		}
		if err := tx.QueryRow(ctx, `SELECT domain FROM customers WHERE id = $1`, cid).Scan(&ix.domain); err != nil {
			return nil, err
		}
	}
	rows, err := tx.Query(ctx, `
		SELECT p.id::text, p.customer_id::text, p.name, coalesce(d.username, '')
		  FROM people p LEFT JOIN device_accounts d ON d.person_id = p.id
		 WHERE p.customer_id IS NULL OR p.customer_id = $1`, nullIfEmpty(cid))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var rp refPerson
		if err := rows.Scan(&id, &rp.CustomerID, &rp.Name, &rp.Username); err != nil {
			return nil, err
		}
		ix.people[id] = rp
	}
	return ix, rows.Err()
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (ix *refIndex) label(field, ref string) RefLabel {
	if l, ok := predefined[field][ref]; ok {
		l.Kind = "predefinido"
		return l
	}
	kind, val := splitRef(ref)
	gone := RefLabel{Label: "(removido)", Sub: ref, Kind: kind, Missing: true}
	scopeTag := func(cid *string) string {
		if cid == nil {
			return "global"
		}
		return "cliente"
	}
	switch kind {
	case "user":
		p, ok := ix.people[val]
		if !ok {
			return gone
		}
		l := RefLabel{Label: p.Username, Sub: p.Name, Kind: "usuario"}
		if p.Username == "" {
			l.Label, l.Sub = p.Name, "sem acesso aos equipamentos"
		}
		return l
	case "group", "net", "profile", "schedule":
		o, ok := ix.objects[val]
		if !ok {
			return gone
		}
		l := RefLabel{Label: o.Name, Sub: objectKinds[o.Kind] + " · " + scopeTag(o.CustomerID), Kind: o.Kind}
		switch o.Kind {
		case kindUserGroup:
			dom := GlobalDomain
			if o.CustomerID != nil {
				dom = ix.domain
			}
			l.Label = "Grupo " + o.Name + " @" + dom
			l.Sub = fmt.Sprintf("%d técnicos · %s", len(o.Members), scopeTag(o.CustomerID))
		case kindNetwork:
			var d networkData
			_ = json.Unmarshal(o.Data, &d)
			l.Sub = strings.Join(d.CIDRs, ", ")
		case kindProfile:
			var d profileData
			_ = json.Unmarshal(o.Data, &d)
			l.Sub = fmt.Sprintf("priv %d · %s", d.PrivLevel, profileSummary(d))
		}
		return l
	case "device":
		d, ok := ix.devices[val]
		if !ok {
			return gone
		}
		return RefLabel{Label: d.Name, Sub: strings.TrimSpace("Equipamento · " + d.Vendor + " " + d.Model + " · " + d.Address), Kind: "device"}
	case "vendor":
		return RefLabel{Label: "Fabricante " + val, Sub: "todos os equipamentos " + val, Kind: "vendor"}
	case "cidr":
		return RefLabel{Label: val, Sub: "faixa de IP", Kind: "cidr"}
	}
	return gone
}

func profileSummary(d profileData) string {
	switch {
	case len(d.Allow) == 0 && len(d.Deny) == 0:
		return "todos os comandos"
	case len(d.Allow) > 0:
		return fmt.Sprintf("%d padrões permitidos", len(d.Allow))
	default:
		return fmt.Sprintf("tudo, exceto %d padrões", len(d.Deny))
	}
}

// checkRule valida as referências de uma regra no seu escopo (cid == "" para global).
func (ix *refIndex) checkRule(r *AAARule, cid string) error {
	bad := func(field, ref string) error {
		return validationError(fmt.Sprintf("Regra %q: %s %q não pode ser usado aqui.", r.Name, field, ref))
	}
	inScope := func(o *AAAObject, allowGlobal bool) bool {
		if o.CustomerID == nil {
			return allowGlobal
		}
		return cid != "" && *o.CustomerID == cid
	}
	for _, ref := range r.Who {
		kind, val := splitRef(ref)
		switch {
		case ref == policy.RefAll || ref == policy.RefNone:
		case kind == "user":
			p, ok := ix.people[val]
			if !ok || scopeKey(p.CustomerID) != cid {
				return bad("Quem", ref)
			}
		case kind == "group":
			o, ok := ix.objects[val]
			// Regras do cliente só usam técnicos do domínio do cliente; as globais, só do domínio global.
			if !ok || o.Kind != kindUserGroup || scopeKey(o.CustomerID) != cid {
				return bad("Quem", ref)
			}
		default:
			return bad("Quem", ref)
		}
	}
	for _, ref := range r.Where {
		kind, val := splitRef(ref)
		switch {
		case ref == policy.RefAll || ref == policy.RefNone:
		case kind == "vendor" && strings.TrimSpace(val) != "":
		case kind == "device":
			if _, ok := ix.devices[val]; !ok || cid == "" {
				return bad("Onde", ref)
			}
		case kind == "group":
			o, ok := ix.objects[val]
			if !ok || o.Kind != kindDeviceGroup || !inScope(o, true) {
				return bad("Onde", ref)
			}
		default:
			return bad("Onde", ref)
		}
	}
	for _, ref := range r.From {
		kind, val := splitRef(ref)
		switch {
		case ref == policy.RefAll || ref == policy.RefNone:
		case kind == "cidr":
			if policy.ValidateCIDR(val) != nil {
				return bad("De onde", ref)
			}
		case kind == "net":
			o, ok := ix.objects[val]
			if !ok || o.Kind != kindNetwork || !inScope(o, true) {
				return bad("De onde", ref)
			}
		default:
			return bad("De onde", ref)
		}
	}
	if r.What != "" && r.What != policy.RefNone {
		kind, val := splitRef(r.What)
		o, ok := ix.objects[val]
		if kind != "profile" || !ok || o.Kind != kindProfile || !inScope(o, true) {
			return bad("O que", r.What)
		}
	}
	for _, ref := range r.When {
		kind, val := splitRef(ref)
		switch {
		case ref == policy.RefAlways || ref == policy.RefNever:
		case kind == "schedule":
			o, ok := ix.objects[val]
			if !ok || o.Kind != kindSchedule || !inScope(o, true) {
				return bad("Quando", ref)
			}
		default:
			return bad("Quando", ref)
		}
	}
	return nil
}

// ruleDiff compara o rascunho com a última publicação.
type ruleDiff struct {
	Kind string `json:"kind"` // nova | alterada | removida | ordem
	Name string `json:"name"`
}

func diffRules(published, draft []AAARule) []ruleDiff {
	out := []ruleDiff{}
	before := map[string]AAARule{}
	var orderBefore, orderAfter []string
	for _, r := range published {
		before[r.ID] = r
		orderBefore = append(orderBefore, r.ID)
	}
	seen := map[string]bool{}
	for _, r := range draft {
		seen[r.ID] = true
		b, ok := before[r.ID]
		switch {
		case !ok:
			out = append(out, ruleDiff{"nova", r.Name})
		case !sameRule(b, r):
			out = append(out, ruleDiff{"alterada", r.Name})
		}
		if ok {
			orderAfter = append(orderAfter, r.ID)
		}
	}
	for _, r := range published {
		if !seen[r.ID] {
			out = append(out, ruleDiff{"removida", r.Name})
		}
	}
	// Ordem relativa das regras que continuam
	var kept []string
	for _, id := range orderBefore {
		if seen[id] {
			kept = append(kept, id)
		}
	}
	if strings.Join(kept, ",") != strings.Join(orderAfter, ",") {
		out = append(out, ruleDiff{"ordem", "A ordem das regras mudou"})
	}
	return out
}

func sameRule(a, b AAARule) bool {
	norm := func(r AAARule) string {
		r.CustomerID = nil
		sorted := func(xs []string) []string {
			c := append([]string{}, xs...)
			sort.Strings(c)
			return c
		}
		r.Who, r.Where, r.From, r.When = sorted(r.Who), sorted(r.Where), sorted(r.From), sorted(r.When)
		j, _ := json.Marshal(r)
		return string(j)
	}
	return norm(a) == norm(b)
}
