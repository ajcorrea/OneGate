package platform

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// GlobalDomain é o domínio dos acessos globais (equipe ON TELECOM).
var GlobalDomain = func() string {
	if d := os.Getenv("ONEGATE_GLOBAL_DOMAIN"); d != "" {
		return strings.ToLower(d)
	}
	return "onegate.systems"
}()

// Function é uma função do painel (folha da árvore de permissões).
type Function struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Platform marca funções que só fazem sentido no escopo da plataforma (não por cliente).
	Platform bool `json:"platform,omitempty"`
}

// Menu agrupa funções na árvore.
type Menu struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Functions []Function `json:"functions"`
}

// Catalog é a árvore de menus e funções do painel. Novas telas acrescentam funções aqui.
var Catalog = []Menu{
	{ID: "overview", Label: "Visão geral", Functions: []Function{{ID: "overview.view", Label: "Ver painel e indicadores"}}},
	{ID: "aaa", Label: "Acesso à rede (AAA)", Functions: []Function{
		{ID: "aaa.dashboard", Label: "Painel AAA: ver"},
		{ID: "aaa.devices.view", Label: "Equipamentos: ver"},
		{ID: "aaa.devices.edit", Label: "Equipamentos: cadastrar e editar"},
		{ID: "aaa.devices.secret", Label: "Equipamentos: rotacionar chave"},
		{ID: "aaa.rules.view", Label: "Regras de acesso: ver"},
		{ID: "aaa.rules.edit", Label: "Regras de acesso: editar rascunho"},
		{ID: "aaa.rules.publish", Label: "Regras de acesso: publicar nos Edges"},
		{ID: "aaa.users.manage", Label: "Usuários AAA: cadastrar e editar"},
		{ID: "aaa.users.totp", Label: "Usuários AAA: redefinir TOTP"},
		{ID: "aaa.mfa.disable", Label: "Desligar MFA de equipamento"},
		{ID: "aaa.log.view", Label: "Log de comandos: ver"},
	}},
	{ID: "servers", Label: "Servidores", Functions: []Function{
		{ID: "servers.view", Label: "Servidores e saúde: ver"},
		{ID: "servers.install", Label: "Instalar agente"},
		{ID: "servers.logs", Label: "Logs: ver"},
		{ID: "servers.updates", Label: "Atualizações: aplicar"},
	}},
	{ID: "commands", Label: "Comandos em massa", Functions: []Function{
		{ID: "commands.view", Label: "Tarefas: ver"},
		{ID: "commands.run", Label: "Executar comandos prontos"},
		{ID: "commands.free", Label: "Executar comando livre"},
		{ID: "commands.approve", Label: "Aprovar tarefa de outra pessoa"},
	}},
	{ID: "admin", Label: "Administração", Functions: []Function{
		{ID: "admin.customers.view", Label: "Clientes: ver"},
		{ID: "admin.customers.edit", Label: "Clientes: cadastrar e editar", Platform: true},
		{ID: "admin.people.view", Label: "Pessoas e permissões: ver"},
		{ID: "admin.people.edit", Label: "Pessoas e permissões: gerenciar"},
		{ID: "admin.totp.reset", Label: "Redefinir TOTP do painel de outra pessoa"},
		{ID: "admin.params", Label: "Parâmetros do sistema: alterar", Platform: true},
		{ID: "admin.audit.view", Label: "Auditoria: ver"},
		{ID: "admin.audit.export", Label: "Auditoria: exportar"},
	}},
}

var catalogIndex = func() map[string]Function {
	m := map[string]Function{}
	for _, menu := range Catalog {
		for _, f := range menu.Functions {
			m[f.ID] = f
		}
	}
	return m
}()

// ValidFunction informa se a função existe no catálogo.
func ValidFunction(id string) bool { _, ok := catalogIndex[id]; return ok }

func allFunctions() []string {
	var out []string
	for _, menu := range Catalog {
		for _, f := range menu.Functions {
			out = append(out, f.ID)
		}
	}
	return out
}

// builtinTypes são os tipos prontos. As permissões podem ser ajustadas depois no painel
// (exceto o Admin global, que é sempre total).
var builtinTypes = []struct {
	Key, Name, Desc, Scope string
	Full                   bool
	Grants                 []string
}{
	{"global_admin", "Admin global", "Tudo, em todos os clientes. Não pode ser restringido.", "global", true, nil},
	{"global_operator", "Operador global", "Todos os clientes, funções de operação (parâmetros do sistema, redefinir TOTP, desligar MFA de equipamento).", "global", false,
		[]string{"overview.view", "aaa.dashboard", "aaa.devices.view", "aaa.rules.view", "aaa.users.totp", "aaa.mfa.disable", "aaa.log.view",
			"servers.view", "servers.logs", "commands.view", "admin.customers.view", "admin.people.view", "admin.totp.reset", "admin.params", "admin.audit.view"}},
	{"customer_admin", "Admin do cliente", "Tudo, só nos clientes atribuídos.", "customer", false, nil}, // preenchido abaixo
	{"customer_operator", "Operador do cliente", "Operação limitada, só nos clientes atribuídos.", "customer", false,
		[]string{"overview.view", "aaa.dashboard", "aaa.devices.view", "aaa.log.view", "servers.view", "servers.logs", "commands.view", "commands.run", "admin.customers.view"}},
}

func init() {
	for i := range builtinTypes {
		if builtinTypes[i].Key == "customer_admin" {
			for _, f := range allFunctions() {
				if !catalogIndex[f].Platform && f != "admin.totp.reset" {
					builtinTypes[i].Grants = append(builtinTypes[i].Grants, f)
				}
			}
		}
	}
}

// EnsureBuiltins cria os tipos prontos que ainda não existem e converte administradores antigos.
func (db *DB) EnsureBuiltins(ctx context.Context) error {
	return db.WithActor(ctx, System, func(tx pgx.Tx) error {
		for _, bt := range builtinTypes {
			var id string
			err := tx.QueryRow(ctx, `INSERT INTO access_types (key, name, description, scope, builtin, full_access)
				VALUES ($1, $2, $3, $4, true, $5) ON CONFLICT (key) DO NOTHING RETURNING id::text`,
				bt.Key, bt.Name, bt.Desc, bt.Scope, bt.Full).Scan(&id)
			if err == pgx.ErrNoRows {
				continue // já existia: mantém as edições feitas no painel
			}
			if err != nil {
				return err
			}
			for _, f := range bt.Grants {
				if _, err := tx.Exec(ctx, `INSERT INTO access_type_grants (type_id, function) VALUES ($1, $2)`, id, f); err != nil {
					return err
				}
			}
		}
		_, err := tx.Exec(ctx, `UPDATE panel_accounts SET access_type_id = (SELECT id FROM access_types WHERE key = 'global_admin'), legacy_admin = false
			WHERE legacy_admin AND access_type_id IS NULL`)
		return err
	})
}

// ---------- Avaliação ----------

// AccessType é um tipo de acesso carregado.
type AccessType struct {
	ID          string          `json:"id"`
	Key         *string         `json:"key"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Scope       string          `json:"scope"` // global | customer
	Builtin     bool            `json:"builtin"`
	FullAccess  bool            `json:"full_access"`
	Grants      map[string]bool `json:"-"`
	GrantList   []string        `json:"grants"`
}

// PanelGroup é um grupo do painel carregado.
type PanelGroup struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	CustomerID  *string           `json:"customer_id"`
	BaseTypeID  string            `json:"base_type_id"`
	Description string            `json:"description"`
	Overrides   map[string]string `json:"overrides"`
	Members     []string          `json:"members"`
	base        *AccessType
}

// Subject é tudo o que define as permissões de uma pessoa no painel.
type Subject struct {
	PersonID   string
	CustomerID *string // domínio da pessoa: nil = global
	Type       *AccessType
	Groups     []*PanelGroup
	Overrides  map[string]string
	Customers  map[string]bool // clientes atribuídos (tipos de escopo por cliente)
}

// Step é um passo da explicação de uma decisão.
type Step struct {
	Level string `json:"level"`
	Value string `json:"value"`
}

// Decision é o resultado de uma consulta de permissão.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Chain   []Step `json:"chain"`
}

// applies diz se uma base (tipo do usuário ou de um grupo) vale no cliente informado ("" = plataforma).
func (s *Subject) typeApplies(t *AccessType, customerID string) bool {
	if t == nil {
		return false
	}
	if t.Scope == "global" {
		return true
	}
	if customerID == "" {
		return false
	}
	if s.CustomerID != nil {
		return *s.CustomerID == customerID
	}
	return s.Customers[customerID]
}

func (s *Subject) groupApplies(g *PanelGroup, customerID string) bool {
	if g.CustomerID != nil {
		return customerID != "" && *g.CustomerID == customerID
	}
	return s.typeApplies(g.base, customerID)
}

// FullAdmin indica Admin global.
func (s *Subject) FullAdmin() bool {
	if s.Type != nil && s.Type.FullAccess {
		return true
	}
	for _, g := range s.Groups {
		if g.base != nil && g.base.FullAccess && g.CustomerID == nil {
			return true
		}
	}
	return false
}

// Global indica que a pessoa enxerga todos os clientes (algum tipo de escopo global).
func (s *Subject) Global() bool {
	if s.Type != nil && s.Type.Scope == "global" {
		return true
	}
	for _, g := range s.Groups {
		if g.CustomerID == nil && g.base != nil && g.base.Scope == "global" {
			return true
		}
	}
	return false
}

// Can avalia uma função num cliente ("" = escopo da plataforma). Ordem: escopo → usuário → grupos
// (negar vence entre grupos) → tipos. O Admin global sempre pode.
func (s *Subject) Can(fn, customerID string) Decision {
	var chain []Step
	if s.FullAdmin() {
		return Decision{Allowed: true, Reason: "Admin global: acesso total", Chain: []Step{{"Tipo Admin global", "Tudo"}}}
	}
	var bases []*AccessType
	var groups []*PanelGroup
	if s.typeApplies(s.Type, customerID) {
		bases = append(bases, s.Type)
	}
	for _, g := range s.Groups {
		if s.groupApplies(g, customerID) {
			groups = append(groups, g)
			bases = append(bases, g.base)
		}
	}
	scope := "a plataforma"
	if customerID != "" {
		scope = "este cliente"
	}
	if len(bases) == 0 {
		return Decision{Reason: "Nenhum tipo de acesso alcança " + scope, Chain: []Step{{"Escopo", "Fora do escopo"}}}
	}
	chain = append(chain, Step{"Escopo", "Dentro do escopo"})
	if fn == "admin.customers.edit" || fn == "admin.params" {
		if customerID != "" {
			return Decision{Reason: "Função da plataforma: não é concedida por cliente", Chain: chain}
		}
	}
	if v, ok := s.Overrides[fn]; ok {
		chain = append(chain, Step{"Usuário", effectLabel(v)})
		return Decision{Allowed: v == "allow", Reason: effectLabel(v) + " neste usuário", Chain: chain}
	}
	chain = append(chain, Step{"Usuário", "Herdar"})
	var allowBy, denyBy string
	for _, g := range groups {
		v := g.Overrides[fn]
		chain = append(chain, Step{"Grupo " + g.Name, effectLabel(v)})
		if v == "deny" && denyBy == "" {
			denyBy = g.Name
		} else if v == "allow" && allowBy == "" {
			allowBy = g.Name
		}
	}
	if denyBy != "" {
		return Decision{Reason: "Negado pelo grupo " + denyBy, Chain: chain}
	}
	if allowBy != "" {
		return Decision{Allowed: true, Reason: "Permitido pelo grupo " + allowBy, Chain: chain}
	}
	for _, t := range bases {
		has := t.Grants[fn]
		v := "Não incluído"
		if has {
			v = "Incluído"
		}
		chain = append(chain, Step{"Tipo " + t.Name, v})
		if has {
			return Decision{Allowed: true, Reason: "Herdado do tipo " + t.Name, Chain: chain}
		}
	}
	return Decision{Reason: "Nenhum tipo de acesso inclui esta função", Chain: chain}
}

func effectLabel(v string) string {
	switch v {
	case "allow":
		return "Permitir"
	case "deny":
		return "Negar"
	}
	return "Herdar"
}

// Functions devolve as funções permitidas num cliente ("" = plataforma).
func (s *Subject) Functions(customerID string) []string {
	out := []string{}
	for _, f := range allFunctions() {
		if s.Can(f, customerID).Allowed {
			out = append(out, f)
		}
	}
	return out
}

// ---------- Carga do banco ----------

func loadTypes(ctx context.Context, q pgx.Tx) (map[string]*AccessType, error) {
	rows, err := q.Query(ctx, `SELECT id::text, key, name, description, scope, builtin, full_access FROM access_types ORDER BY builtin DESC, name`)
	if err != nil {
		return nil, err
	}
	types := map[string]*AccessType{}
	for rows.Next() {
		t := &AccessType{Grants: map[string]bool{}, GrantList: []string{}}
		if err := rows.Scan(&t.ID, &t.Key, &t.Name, &t.Description, &t.Scope, &t.Builtin, &t.FullAccess); err != nil {
			rows.Close()
			return nil, err
		}
		types[t.ID] = t
	}
	rows.Close()
	g, err := q.Query(ctx, `SELECT type_id::text, function FROM access_type_grants`)
	if err != nil {
		return nil, err
	}
	defer g.Close()
	for g.Next() {
		var id, fn string
		if err := g.Scan(&id, &fn); err != nil {
			return nil, err
		}
		if t := types[id]; t != nil && ValidFunction(fn) {
			t.Grants[fn] = true
		}
	}
	for _, t := range types {
		if t.FullAccess {
			for _, f := range allFunctions() {
				t.Grants[f] = true
			}
		}
		for f := range t.Grants {
			t.GrantList = append(t.GrantList, f)
		}
		sort.Strings(t.GrantList)
	}
	return types, g.Err()
}

func loadGroups(ctx context.Context, q pgx.Tx, types map[string]*AccessType) (map[string]*PanelGroup, error) {
	rows, err := q.Query(ctx, `SELECT id::text, name, customer_id::text, base_type_id::text, description FROM panel_groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	groups := map[string]*PanelGroup{}
	for rows.Next() {
		g := &PanelGroup{Overrides: map[string]string{}, Members: []string{}}
		if err := rows.Scan(&g.ID, &g.Name, &g.CustomerID, &g.BaseTypeID, &g.Description); err != nil {
			rows.Close()
			return nil, err
		}
		g.base = types[g.BaseTypeID]
		groups[g.ID] = g
	}
	rows.Close()
	ov, err := q.Query(ctx, `SELECT group_id::text, function, effect FROM panel_group_overrides`)
	if err != nil {
		return nil, err
	}
	for ov.Next() {
		var id, fn, eff string
		if err := ov.Scan(&id, &fn, &eff); err != nil {
			ov.Close()
			return nil, err
		}
		if g := groups[id]; g != nil {
			g.Overrides[fn] = eff
		}
	}
	ov.Close()
	mem, err := q.Query(ctx, `SELECT group_id::text, person_id::text FROM panel_group_members`)
	if err != nil {
		return nil, err
	}
	defer mem.Close()
	for mem.Next() {
		var gid, pid string
		if err := mem.Scan(&gid, &pid); err != nil {
			return nil, err
		}
		if g := groups[gid]; g != nil {
			g.Members = append(g.Members, pid)
		}
	}
	return groups, mem.Err()
}

// loadSubject carrega as permissões de uma pessoa.
func loadSubject(ctx context.Context, q pgx.Tx, personID string) (*Subject, error) {
	types, err := loadTypes(ctx, q)
	if err != nil {
		return nil, err
	}
	groups, err := loadGroups(ctx, q, types)
	if err != nil {
		return nil, err
	}
	return loadSubjectWith(ctx, q, personID, types, groups)
}

func loadSubjectWith(ctx context.Context, q pgx.Tx, personID string, types map[string]*AccessType, groups map[string]*PanelGroup) (*Subject, error) {
	s := &Subject{PersonID: personID, Overrides: map[string]string{}, Customers: map[string]bool{}}
	var typeID *string
	if err := q.QueryRow(ctx, `SELECT p.customer_id::text, a.access_type_id::text FROM people p JOIN panel_accounts a ON a.person_id = p.id WHERE p.id = $1`, personID).
		Scan(&s.CustomerID, &typeID); err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if typeID != nil {
		s.Type = types[*typeID]
	}
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		g := groups[id]
		for _, m := range g.Members {
			if m == personID {
				s.Groups = append(s.Groups, g)
				break
			}
		}
	}
	rows, err := q.Query(ctx, `SELECT function, effect FROM panel_user_overrides WHERE person_id = $1`, personID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var fn, eff string
		if err := rows.Scan(&fn, &eff); err != nil {
			rows.Close()
			return nil, err
		}
		s.Overrides[fn] = eff
	}
	rows.Close()
	cr, err := q.Query(ctx, `SELECT customer_id::text FROM panel_user_customers WHERE person_id = $1`, personID)
	if err != nil {
		return nil, err
	}
	defer cr.Close()
	for cr.Next() {
		var c string
		if err := cr.Scan(&c); err != nil {
			return nil, err
		}
		s.Customers[c] = true
	}
	return s, cr.Err()
}

// errForbidden indica falta de permissão para a função.
type forbiddenError string

func (e forbiddenError) Error() string { return string(e) }

func forbidden(fn string) error {
	return forbiddenError(fmt.Sprintf("Você não tem permissão para isso (%s).", catalogIndex[fn].Label))
}
