package platform

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ajcorrea/onegate/internal/passhash"
	"github.com/ajcorrea/onegate/internal/totp"
)

// Person é uma pessoa de um domínio: global (@onegate.systems) ou de um cliente.
// Os dois acessos (painel e equipamentos) são independentes e opcionais.
type Person struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Email      *string       `json:"email"` // contato
	Phone      *string       `json:"phone"`
	Active     bool          `json:"active"`
	CreatedAt  time.Time     `json:"created_at"`
	CustomerID *string       `json:"customer_id"` // nulo = domínio global
	Domain     string        `json:"domain"`
	Panel      *PanelAccess  `json:"panel"`
	Device     *DeviceAccess `json:"device"`
}

// PanelAccess é o acesso ao painel ONE GATE.
type PanelAccess struct {
	Login        string            `json:"login"`
	Active       bool              `json:"active"`
	TOTPEnabled  bool              `json:"totp_enabled"`
	LastLoginAt  *time.Time        `json:"last_login_at"`
	AccessTypeID *string           `json:"access_type_id"`
	GroupIDs     []string          `json:"group_ids"`
	CustomerIDs  []string          `json:"customer_ids"` // clientes atribuídos (tipos de escopo por cliente)
	Overrides    map[string]string `json:"overrides"`
}

// DeviceAccess é a credencial usada nos equipamentos e servidores dos clientes.
type DeviceAccess struct {
	Username          string    `json:"username"` // usuario@dominio
	Active            bool      `json:"active"`
	TOTPConfigured    bool      `json:"totp_configured"`
	PasswordChangedAt time.Time `json:"password_changed_at"`
}

var (
	emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	localRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)
)

const minPasswordLen = 12

func validatePassword(pw string) error {
	if len([]rune(pw)) < minPasswordLen {
		return validationError("A senha precisa de pelo menos 12 caracteres.")
	}
	return nil
}

func personID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		writeError(w, http.StatusNotFound, "Não encontrado.")
		return "", false
	}
	return id, true
}

func optional(s *string) *string {
	if s == nil {
		return nil
	}
	v := strings.TrimSpace(*s)
	if v == "" {
		return nil
	}
	return &v
}

// localPart valida e normaliza a parte antes do @ (aceita o login completo, se o domínio bater).
func localPart(in, domain string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(in))
	if i := strings.Index(v, "@"); i >= 0 {
		if v[i+1:] != domain {
			return "", validationError("O login deve terminar em @" + domain + ".")
		}
		v = v[:i]
	}
	if !localRe.MatchString(v) {
		return "", validationError("Usuário inválido: 2 a 32 caracteres, letras minúsculas, números, ponto, hífen ou sublinhado.")
	}
	return v, nil
}

func loadPeople(ctx context.Context, tx pgx.Tx, id string) ([]Person, error) {
	rows, err := tx.Query(ctx, `
		SELECT p.id::text, p.name, p.email, p.phone, p.active, p.created_at, p.customer_id::text, coalesce(c.domain, $2),
		       a.login, a.active, a.totp_enabled, a.last_login_at, a.access_type_id::text,
		       d.username, d.active, d.totp_secret IS NOT NULL, d.password_changed_at
		FROM people p
		LEFT JOIN customers c ON c.id = p.customer_id
		LEFT JOIN panel_accounts a ON a.person_id = p.id
		LEFT JOIN device_accounts d ON d.person_id = p.id
		WHERE ($1 = '' OR p.id::text = $1)
		ORDER BY p.name`, id, GlobalDomain)
	if err != nil {
		return nil, err
	}
	var out []Person
	idx := map[string]int{}
	for rows.Next() {
		var p Person
		var login, username, typeID *string
		var pActive, pTOTP, dActive, dTOTP *bool
		var lastLogin, pwChanged *time.Time
		if err := rows.Scan(&p.ID, &p.Name, &p.Email, &p.Phone, &p.Active, &p.CreatedAt, &p.CustomerID, &p.Domain,
			&login, &pActive, &pTOTP, &lastLogin, &typeID, &username, &dActive, &dTOTP, &pwChanged); err != nil {
			rows.Close()
			return nil, err
		}
		if login != nil {
			p.Panel = &PanelAccess{Login: *login, Active: *pActive, TOTPEnabled: *pTOTP, LastLoginAt: lastLogin, AccessTypeID: typeID,
				GroupIDs: []string{}, CustomerIDs: []string{}, Overrides: map[string]string{}}
		}
		if username != nil {
			p.Device = &DeviceAccess{Username: *username, Active: *dActive, TOTPConfigured: *dTOTP, PasswordChangedAt: *pwChanged}
		}
		idx[p.ID] = len(out)
		out = append(out, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	fill := func(sql string, f func(p *PanelAccess, a, b string)) error {
		rs, err := tx.Query(ctx, sql)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var pid, a, b string
			if err := rs.Scan(&pid, &a, &b); err != nil {
				return err
			}
			if i, ok := idx[pid]; ok && out[i].Panel != nil {
				f(out[i].Panel, a, b)
			}
		}
		return rs.Err()
	}
	if err := fill(`SELECT person_id::text, group_id::text, '' FROM panel_group_members ORDER BY group_id`, func(p *PanelAccess, a, _ string) { p.GroupIDs = append(p.GroupIDs, a) }); err != nil {
		return nil, err
	}
	if err := fill(`SELECT person_id::text, customer_id::text, '' FROM panel_user_customers ORDER BY customer_id`, func(p *PanelAccess, a, _ string) { p.CustomerIDs = append(p.CustomerIDs, a) }); err != nil {
		return nil, err
	}
	if err := fill(`SELECT person_id::text, function, effect FROM panel_user_overrides`, func(p *PanelAccess, a, b string) { p.Overrides[a] = b }); err != nil {
		return nil, err
	}
	return out, nil
}

func loadPerson(ctx context.Context, tx pgx.Tx, id string) (Person, error) {
	ps, err := loadPeople(ctx, tx, id)
	if err != nil {
		return Person{}, err
	}
	if len(ps) == 0 {
		return Person{}, ErrNotFound
	}
	return ps[0], nil
}

// scopeOf é o escopo em que se avalia quem pode gerenciar a pessoa: plataforma (global) ou o cliente do domínio.
func scopeOf(p Person) string {
	if p.CustomerID == nil {
		return ""
	}
	return *p.CustomerID
}

func (s *Server) respondPerson(w http.ResponseWriter, r *http.Request, id string, status int) {
	var p Person
	err := s.DB.WithActor(r.Context(), sessionFrom(r).actor(r), func(tx pgx.Tx) error {
		var err error
		p, err = loadPerson(r.Context(), tx, id)
		return err
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, status, p)
}

// withPerson carrega a pessoa e confere a permissão de quem está agindo no escopo dela.
func (s *Server) withPerson(r *http.Request, tx pgx.Tx, id, fn string) (Person, error) {
	p, err := loadPerson(r.Context(), tx, id)
	if err != nil {
		return p, err
	}
	if !sessionFrom(r).can(fn, scopeOf(p)) {
		if !sessionFrom(r).can("admin.people.view", scopeOf(p)) {
			return p, ErrNotFound
		}
		return p, forbidden(fn)
	}
	return p, nil
}

func (s *Server) handleListPeople(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	out := []Person{}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		all, err := loadPeople(r.Context(), tx, "")
		if err != nil {
			return err
		}
		for _, p := range all {
			if sess.can("admin.people.view", scopeOf(p)) {
				out = append(out, p)
			}
		}
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type personInput struct {
	Name       *string `json:"name"`
	Email      *string `json:"email"`
	Phone      *string `json:"phone"`
	Active     *bool   `json:"active"`
	CustomerID *string `json:"customer_id"` // só na criação; vazio = domínio global
}

func (in personInput) validate() error {
	if in.Name != nil && len([]rune(strings.TrimSpace(*in.Name))) < 2 {
		return validationError("Informe o nome.")
	}
	if e := optional(in.Email); e != nil && !emailRe.MatchString(*e) {
		return validationError("E-mail de contato inválido.")
	}
	return nil
}

func (s *Server) handleCreatePerson(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var in personInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if in.Name == nil {
		writeError(w, http.StatusBadRequest, "Informe o nome.")
		return
	}
	if err := in.validate(); err != nil {
		s.serverError(w, r, err)
		return
	}
	cid := optional(in.CustomerID)
	scope := ""
	if cid != nil {
		if !uuidRe.MatchString(*cid) {
			writeError(w, http.StatusBadRequest, "Cliente inválido.")
			return
		}
		scope = *cid
	}
	if !sess.can("admin.people.edit", scope) {
		s.serverError(w, r, forbidden("admin.people.edit"))
		return
	}
	var id string
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		if cid != nil {
			if _, err := scanCustomer(tx.QueryRow(r.Context(), `SELECT `+customerCols+` FROM customers WHERE id = $1`, *cid)); err != nil {
				return validationError("Cliente inexistente.")
			}
		}
		if err := tx.QueryRow(r.Context(), `INSERT INTO people (name, email, phone, customer_id) VALUES ($1, $2, $3, $4) RETURNING id::text`,
			strings.TrimSpace(*in.Name), optional(in.Email), optional(in.Phone), cid).Scan(&id); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), cid, "pessoa.criada", "person", id, map[string]any{"name": strings.TrimSpace(*in.Name)})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusCreated)
}

func (s *Server) handleUpdatePerson(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	var in personInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := in.validate(); err != nil {
		s.serverError(w, r, err)
		return
	}
	if in.CustomerID != nil {
		writeError(w, http.StatusBadRequest, "O domínio de uma pessoa não pode ser trocado. Cadastre outra pessoa.")
		return
	}
	if id == sess.UserID && in.Active != nil && !*in.Active {
		writeError(w, http.StatusBadRequest, "Você não pode desativar a si mesmo.")
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := s.withPerson(r, tx, id, "admin.people.edit")
		if err != nil {
			return err
		}
		changes := map[string]any{}
		name, email, phone, active := p.Name, p.Email, p.Phone, p.Active
		if in.Name != nil {
			name, changes["name"] = strings.TrimSpace(*in.Name), strings.TrimSpace(*in.Name)
		}
		if in.Email != nil {
			email, changes["email"] = optional(in.Email), optional(in.Email)
		}
		if in.Phone != nil {
			phone, changes["phone"] = optional(in.Phone), "alterado"
		}
		if in.Active != nil && *in.Active != p.Active {
			active, changes["active"] = *in.Active, *in.Active
		}
		if len(changes) == 0 {
			return nil
		}
		if _, err := tx.Exec(r.Context(), `UPDATE people SET name=$2, email=$3, phone=$4, active=$5, updated_at=now() WHERE id=$1`, id, name, email, phone, active); err != nil {
			return err
		}
		if !active {
			if _, err := tx.Exec(r.Context(), `DELETE FROM sessions WHERE person_id = $1`, id); err != nil {
				return err
			}
		}
		return audit(r.Context(), tx, sess.actor(r), p.CustomerID, "pessoa.alterada", "person", id, changes)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

// ---------- Acesso ao painel ----------

// NewPanelUser cria uma pessoa global já com acesso ao painel (bootstrap do primeiro administrador).
type NewPanelUser struct {
	Name     string
	Email    string // contato
	Login    string // parte antes do @ (o domínio é o global)
	Password string
	TypeKey  string // ex.: global_admin
}

// CreatePanelUser cria a pessoa global e o acesso ao painel numa única transação.
func (s *Server) CreatePanelUser(ctx context.Context, a Actor, in NewPanelUser) (string, error) {
	if len([]rune(strings.TrimSpace(in.Name))) < 2 {
		return "", validationError("Informe o nome.")
	}
	local, err := localPart(in.Login, GlobalDomain)
	if err != nil {
		return "", err
	}
	if err := validatePassword(in.Password); err != nil {
		return "", err
	}
	hash, err := passhash.Hash(in.Password)
	if err != nil {
		return "", err
	}
	login := local + "@" + GlobalDomain
	var id string
	err = s.DB.WithActor(ctx, a, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO people (name, email) VALUES ($1, $2) RETURNING id::text`, strings.TrimSpace(in.Name), optional(&in.Email)).Scan(&id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO panel_accounts (person_id, login, password_hash, access_type_id)
			VALUES ($1, $2, $3, (SELECT id FROM access_types WHERE key = NULLIF($4, '')))`, id, login, hash, in.TypeKey)
		if uniqueViolation(err) {
			return conflictError("Já existe um acesso ao painel com este login.")
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, a, nil, "painel.acesso_criado", "person", id, map[string]any{"login": login, "tipo": in.TypeKey})
	})
	return id, err
}

type panelInput struct {
	Login        string   `json:"login"` // parte antes do @, ou o login completo
	Password     *string  `json:"password"`
	Active       *bool    `json:"active"` // padrão: true
	AccessTypeID *string  `json:"access_type_id"`
	GroupIDs     []string `json:"group_ids"`
	CustomerIDs  []string `json:"customer_ids"`
}

// checkAssignments impede atribuições incoerentes com o domínio e escalada de privilégio.
func checkAssignments(sess *Session, p Person, types map[string]*AccessType, groups map[string]*PanelGroup, typeID *string, groupIDs, customerIDs []string) error {
	var picked []*AccessType
	if typeID != nil {
		t := types[*typeID]
		if t == nil {
			return validationError("Tipo de acesso inexistente.")
		}
		picked = append(picked, t)
	}
	for _, gid := range groupIDs {
		g := groups[gid]
		if g == nil {
			return validationError("Grupo inexistente.")
		}
		if p.CustomerID != nil && (g.CustomerID == nil || *g.CustomerID != *p.CustomerID) {
			return validationError("Pessoa de domínio de cliente só entra em grupos do próprio cliente.")
		}
		if p.CustomerID == nil && g.CustomerID != nil {
			return validationError("Pessoa do domínio global só entra em grupos globais.")
		}
		picked = append(picked, g.base)
	}
	for _, t := range picked {
		if t == nil {
			continue
		}
		if p.CustomerID != nil && t.Scope == "global" {
			return validationError("Pessoa de domínio de cliente só pode ter tipos de escopo por cliente.")
		}
		if (t.Scope == "global" || t.FullAccess) && !sess.IsAdmin {
			return forbiddenError("Só o Admin global atribui tipos de acesso globais.")
		}
	}
	if p.CustomerID != nil && len(customerIDs) > 0 {
		return validationError("Pessoa de domínio de cliente já pertence ao próprio cliente; não atribua outros.")
	}
	for _, c := range customerIDs {
		if !uuidRe.MatchString(c) {
			return validationError("Cliente inválido.")
		}
		if !sess.can("admin.people.edit", c) {
			return forbidden("admin.people.edit")
		}
	}
	return nil
}

// handlePutPanel cria ou altera o acesso ao painel: login, senha, tipo, grupos e clientes.
func (s *Server) handlePutPanel(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	var in panelInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	active := in.Active == nil || *in.Active
	if in.GroupIDs == nil {
		in.GroupIDs = []string{}
	}
	if in.CustomerIDs == nil {
		in.CustomerIDs = []string{}
	}
	sort.Strings(in.GroupIDs)
	sort.Strings(in.CustomerIDs)
	in.AccessTypeID = optional(in.AccessTypeID)
	hash := ""
	if in.Password != nil {
		if err := validatePassword(*in.Password); err != nil {
			s.serverError(w, r, err)
			return
		}
		var err error
		if hash, err = passhash.Hash(*in.Password); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := s.withPerson(r, tx, id, "admin.people.edit")
		if err != nil {
			return err
		}
		local, err := localPart(in.Login, p.Domain)
		if err != nil {
			return err
		}
		login := local + "@" + p.Domain
		types, err := loadTypes(r.Context(), tx)
		if err != nil {
			return err
		}
		groups, err := loadGroups(r.Context(), tx, types)
		if err != nil {
			return err
		}
		permsChanged := p.Panel == nil || !eqPtr(p.Panel.AccessTypeID, in.AccessTypeID) || !eqList(p.Panel.GroupIDs, in.GroupIDs) || !eqList(p.Panel.CustomerIDs, in.CustomerIDs)
		if permsChanged && id == sess.UserID {
			return validationError("Você não pode alterar as próprias permissões.")
		}
		if permsChanged {
			if err := checkAssignments(sess, p, types, groups, in.AccessTypeID, in.GroupIDs, in.CustomerIDs); err != nil {
				return err
			}
		}
		if id == sess.UserID && !active {
			return validationError("Você não pode desativar o próprio acesso.")
		}
		changes := map[string]any{}
		revoke := false
		if p.Panel == nil {
			if hash == "" {
				return validationError("Defina a senha inicial do painel.")
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO panel_accounts (person_id, login, password_hash, active, access_type_id) VALUES ($1, $2, $3, $4, $5)`,
				id, login, hash, active, in.AccessTypeID)
			changes["login"], changes["active"] = login, active
		} else {
			if login != p.Panel.Login {
				changes["login"] = login
			}
			if active != p.Panel.Active {
				changes["active"] = active
				revoke = !active
			}
			if hash != "" {
				changes["password"] = "alterada"
				revoke = true
			}
			_, err = tx.Exec(r.Context(), `UPDATE panel_accounts SET login=$2, active=$3, access_type_id=$4,
				password_hash = CASE WHEN $5 = '' THEN password_hash ELSE $5 END, updated_at=now() WHERE person_id=$1`,
				id, login, active, in.AccessTypeID, hash)
		}
		if uniqueViolation(err) {
			return conflictError("Já existe um acesso ao painel com o login " + login + ".")
		}
		if err != nil {
			return err
		}
		if permsChanged {
			if _, err := tx.Exec(r.Context(), `DELETE FROM panel_group_members WHERE person_id = $1`, id); err != nil {
				return err
			}
			for _, g := range in.GroupIDs {
				if _, err := tx.Exec(r.Context(), `INSERT INTO panel_group_members (group_id, person_id) VALUES ($1, $2)`, g, id); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(r.Context(), `DELETE FROM panel_user_customers WHERE person_id = $1`, id); err != nil {
				return err
			}
			for _, c := range in.CustomerIDs {
				if _, err := tx.Exec(r.Context(), `INSERT INTO panel_user_customers (person_id, customer_id) VALUES ($1, $2)`, id, c); err != nil {
					return validationError("Cliente inexistente.")
				}
			}
			typeName := "nenhum"
			if in.AccessTypeID != nil {
				typeName = types[*in.AccessTypeID].Name
			}
			changes["tipo"], changes["grupos"], changes["clientes"] = typeName, len(in.GroupIDs), len(in.CustomerIDs)
		}
		if len(changes) == 0 {
			return nil
		}
		if revoke {
			if _, err := tx.Exec(r.Context(), `DELETE FROM sessions WHERE person_id = $1`, id); err != nil {
				return err
			}
		}
		action := "painel.acesso_alterado"
		if p.Panel == nil {
			action = "painel.acesso_criado"
		}
		return audit(r.Context(), tx, sess.actor(r), p.CustomerID, action, "person", id, changes)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

func eqPtr(a, b *string) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

func eqList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// handlePutOverrides define as exceções do usuário (função → allow/deny; ausente = herdar).
func (s *Server) handlePutOverrides(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	var in map[string]string
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if id == sess.UserID {
		writeError(w, http.StatusBadRequest, "Você não pode alterar as próprias permissões.")
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := s.withPerson(r, tx, id, "admin.people.edit")
		if err != nil {
			return err
		}
		if p.Panel == nil {
			return validationError("Esta pessoa não tem acesso ao painel.")
		}
		for fn, eff := range in {
			if !ValidFunction(fn) || (eff != "allow" && eff != "deny") {
				return validationError("Exceção inválida: " + fn)
			}
			// Ninguém concede uma função que não tem no escopo da pessoa.
			if eff == "allow" && !sess.can(fn, scopeOf(p)) {
				return forbiddenError("Você não pode conceder \"" + catalogIndex[fn].Label + "\": você não tem essa função.")
			}
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM panel_user_overrides WHERE person_id = $1`, id); err != nil {
			return err
		}
		for fn, eff := range in {
			if _, err := tx.Exec(r.Context(), `INSERT INTO panel_user_overrides (person_id, function, effect) VALUES ($1, $2, $3)`, id, fn, eff); err != nil {
				return err
			}
		}
		return audit(r.Context(), tx, sess.actor(r), p.CustomerID, "painel.excecoes", "person", id, map[string]any{"excecoes": len(in)})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

func (s *Server) handleDeletePanel(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	if id == sess.UserID {
		writeError(w, http.StatusBadRequest, "Você não pode remover o próprio acesso ao painel.")
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := s.withPerson(r, tx, id, "admin.people.edit")
		if err != nil {
			return err
		}
		if p.Panel == nil {
			return ErrNotFound
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM panel_accounts WHERE person_id = $1`, id); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), p.CustomerID, "painel.acesso_removido", "person", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

// handleResetPanelTOTP apaga o TOTP do painel (celular perdido). No próximo login a pessoa cadastra de novo.
func (s *Server) handleResetPanelTOTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := s.withPerson(r, tx, id, "admin.totp.reset")
		if err != nil {
			return err
		}
		tag, err := tx.Exec(r.Context(), `UPDATE panel_accounts SET totp_secret = NULL, totp_enabled = false, totp_last_step = NULL, updated_at = now() WHERE person_id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM recovery_codes WHERE person_id = $1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM sessions WHERE person_id = $1`, id); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), p.CustomerID, "painel.mfa_redefinido", "person", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

// ---------- Acesso aos equipamentos (usuário AAA) ----------

type deviceInput struct {
	Username string  `json:"username"` // parte antes do @, ou o login completo
	Password *string `json:"password"`
	Active   *bool   `json:"active"` // padrão: true
}

func (s *Server) handlePutDevice(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	var in deviceInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	active := in.Active == nil || *in.Active
	hash := ""
	if in.Password != nil {
		if err := validatePassword(*in.Password); err != nil {
			s.serverError(w, r, err)
			return
		}
		var err error
		if hash, err = passhash.Hash(*in.Password); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := s.withPerson(r, tx, id, "aaa.users.manage")
		if err != nil {
			return err
		}
		local, err := localPart(in.Username, p.Domain)
		if err != nil {
			return err
		}
		username := local + "@" + p.Domain
		changes := map[string]any{}
		if p.Device == nil {
			if hash == "" {
				return validationError("Defina a senha dos equipamentos.")
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO device_accounts (person_id, username, password_hash, active) VALUES ($1, $2, $3, $4)`, id, username, hash, active)
			changes["username"], changes["active"] = username, active
		} else {
			if username != p.Device.Username {
				changes["username"] = username
			}
			if active != p.Device.Active {
				changes["active"] = active
			}
			if hash != "" {
				changes["password"] = "alterada"
			}
			if len(changes) == 0 {
				return nil
			}
			_, err = tx.Exec(r.Context(), `UPDATE device_accounts SET username=$2, active=$3,
				password_hash = CASE WHEN $4 = '' THEN password_hash ELSE $4 END,
				password_changed_at = CASE WHEN $4 = '' THEN password_changed_at ELSE now() END,
				updated_at = now() WHERE person_id = $1`, id, username, active, hash)
		}
		if uniqueViolation(err) {
			return conflictError("O usuário " + username + " já está em uso.")
		}
		if err != nil {
			return err
		}
		action := "equipamentos.acesso_alterado"
		if p.Device == nil {
			action = "equipamentos.acesso_criado"
		}
		return audit(r.Context(), tx, sess.actor(r), p.CustomerID, action, "person", id, changes)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := s.withPerson(r, tx, id, "aaa.users.manage")
		if err != nil {
			return err
		}
		if p.Device == nil {
			return ErrNotFound
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM device_accounts WHERE person_id = $1`, id); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), p.CustomerID, "equipamentos.acesso_removido", "person", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

// handleNewDeviceTOTP gera um TOTP novo para os equipamentos. O segredo só é mostrado nesta resposta.
func (s *Server) handleNewDeviceTOTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sealed, err := s.Box.Seal(secret, deviceCtx(id))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var username string
	err = s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := s.withPerson(r, tx, id, "aaa.users.totp")
		if err != nil {
			return err
		}
		err = tx.QueryRow(r.Context(), `UPDATE device_accounts SET totp_secret = $2, updated_at = now() WHERE person_id = $1 RETURNING username`, id, sealed).Scan(&username)
		if errors.Is(err, pgx.ErrNoRows) {
			return validationError("Crie o acesso aos equipamentos primeiro.")
		}
		if err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), p.CustomerID, "equipamentos.totp_gerado", "person", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":      secret,
		"otpauth_uri": totp.ProvisioningURI(totpIssuer+" (equipamentos)", username, secret),
	})
}
