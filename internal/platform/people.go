package platform

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ajcorrea/onegate/internal/passhash"
	"github.com/ajcorrea/onegate/internal/totp"
)

// Person é uma pessoa da equipe (ou terceiro). Os dois acessos são independentes e opcionais.
type Person struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Email     *string       `json:"email"`
	Phone     *string       `json:"phone"`
	Active    bool          `json:"active"`
	CreatedAt time.Time     `json:"created_at"`
	Panel     *PanelAccess  `json:"panel"`  // nulo = sem acesso ao painel
	Device    *DeviceAccess `json:"device"` // nulo = sem acesso aos equipamentos
}

// PanelAccess é o acesso ao painel ONE GATE.
type PanelAccess struct {
	LoginEmail  string       `json:"login_email"`
	IsAdmin     bool         `json:"is_admin"`
	Active      bool         `json:"active"`
	TOTPEnabled bool         `json:"totp_enabled"`
	LastLoginAt *time.Time   `json:"last_login_at"`
	Permissions []Permission `json:"permissions"`
}

// Permission é o nível de acesso a um módulo do painel num cliente.
type Permission struct {
	CustomerID string `json:"customer_id"`
	Module     string `json:"module"` // aaa | servers | commands | audit
	Level      string `json:"level"`  // read | write
}

// DeviceAccess é a credencial usada nos equipamentos e servidores dos clientes.
type DeviceAccess struct {
	Username          string    `json:"username"`
	Active            bool      `json:"active"`
	TOTPConfigured    bool      `json:"totp_configured"`
	PasswordChangedAt time.Time `json:"password_changed_at"`
	Customers         []string  `json:"customers"` // ids dos clientes onde a credencial vale
}

var (
	emailRe    = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)
	modules    = map[string]bool{"aaa": true, "servers": true, "commands": true, "audit": true}
	levels     = map[string]bool{"read": true, "write": true}
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

// loadPeople carrega pessoas com os dois acessos. ids vazio = todas.
func loadPeople(ctx context.Context, tx pgx.Tx, id string) ([]Person, error) {
	rows, err := tx.Query(ctx, `
		SELECT p.id::text, p.name, p.email, p.phone, p.active, p.created_at,
		       a.login_email, a.is_admin, a.active, a.totp_enabled, a.last_login_at,
		       d.username, d.active, d.totp_secret IS NOT NULL, d.password_changed_at
		FROM people p
		LEFT JOIN panel_accounts a ON a.person_id = p.id
		LEFT JOIN device_accounts d ON d.person_id = p.id
		WHERE ($1 = '' OR p.id::text = $1)
		ORDER BY p.name`, id)
	if err != nil {
		return nil, err
	}
	var out []Person
	idx := map[string]int{}
	for rows.Next() {
		var p Person
		var login, username *string
		var pAdmin, pActive, pTOTP, dActive, dTOTP *bool
		var lastLogin, pwChanged *time.Time
		if err := rows.Scan(&p.ID, &p.Name, &p.Email, &p.Phone, &p.Active, &p.CreatedAt,
			&login, &pAdmin, &pActive, &pTOTP, &lastLogin, &username, &dActive, &dTOTP, &pwChanged); err != nil {
			rows.Close()
			return nil, err
		}
		if login != nil {
			p.Panel = &PanelAccess{LoginEmail: *login, IsAdmin: *pAdmin, Active: *pActive, TOTPEnabled: *pTOTP, LastLoginAt: lastLogin, Permissions: []Permission{}}
		}
		if username != nil {
			p.Device = &DeviceAccess{Username: *username, Active: *dActive, TOTPConfigured: *dTOTP, PasswordChangedAt: *pwChanged, Customers: []string{}}
		}
		idx[p.ID] = len(out)
		out = append(out, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	perms, err := tx.Query(ctx, `SELECT person_id::text, customer_id::text, module, level FROM panel_permissions ORDER BY customer_id, module`)
	if err != nil {
		return nil, err
	}
	for perms.Next() {
		var pid string
		var pm Permission
		if err := perms.Scan(&pid, &pm.CustomerID, &pm.Module, &pm.Level); err != nil {
			perms.Close()
			return nil, err
		}
		if i, ok := idx[pid]; ok && out[i].Panel != nil {
			out[i].Panel.Permissions = append(out[i].Panel.Permissions, pm)
		}
	}
	perms.Close()
	acc, err := tx.Query(ctx, `SELECT person_id::text, customer_id::text FROM device_access`)
	if err != nil {
		return nil, err
	}
	defer acc.Close()
	for acc.Next() {
		var pid, cid string
		if err := acc.Scan(&pid, &cid); err != nil {
			return nil, err
		}
		if i, ok := idx[pid]; ok && out[i].Device != nil {
			out[i].Device.Customers = append(out[i].Device.Customers, cid)
		}
	}
	return out, acc.Err()
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

// respondPerson relê a pessoa (já com as alterações) e responde.
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

func (s *Server) handleListPeople(w http.ResponseWriter, r *http.Request) {
	var out []Person
	err := s.DB.WithActor(r.Context(), sessionFrom(r).actor(r), func(tx pgx.Tx) error {
		var err error
		out, err = loadPeople(r.Context(), tx, "")
		return err
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if out == nil {
		out = []Person{}
	}
	writeJSON(w, http.StatusOK, out)
}

type personInput struct {
	Name   *string `json:"name"`
	Email  *string `json:"email"`
	Phone  *string `json:"phone"`
	Active *bool   `json:"active"`
}

func (in personInput) validate() error {
	if in.Name != nil && len([]rune(strings.TrimSpace(*in.Name))) < 2 {
		return validationError("Informe o nome.")
	}
	if e := optional(in.Email); e != nil && !emailRe.MatchString(*e) {
		return validationError("E-mail inválido.")
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
	var id string
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), `INSERT INTO people (name, email, phone) VALUES ($1, $2, $3) RETURNING id::text`,
			strings.TrimSpace(*in.Name), optional(in.Email), optional(in.Phone)).Scan(&id); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "pessoa.criada", "person", id, map[string]any{"name": strings.TrimSpace(*in.Name)})
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
	if id == sess.UserID && in.Active != nil && !*in.Active {
		writeError(w, http.StatusBadRequest, "Você não pode desativar a si mesmo.")
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := loadPerson(r.Context(), tx, id)
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
		return audit(r.Context(), tx, sess.actor(r), nil, "pessoa.alterada", "person", id, changes)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

// ---------- Acesso ao painel ----------

type panelInput struct {
	LoginEmail string  `json:"login_email"`
	Password   *string `json:"password"`
	IsAdmin    bool    `json:"is_admin"`
	Active     *bool   `json:"active"` // padrão: true
}

// NewPanelUser cria uma pessoa já com acesso ao painel (usado no bootstrap do primeiro administrador).
type NewPanelUser struct {
	Name     string
	Email    string
	Password string
	IsAdmin  bool
}

// CreatePanelUser cria a pessoa e o acesso ao painel numa única transação.
func (s *Server) CreatePanelUser(ctx context.Context, a Actor, in NewPanelUser) (string, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if len([]rune(strings.TrimSpace(in.Name))) < 2 {
		return "", validationError("Informe o nome.")
	}
	if !emailRe.MatchString(email) {
		return "", validationError("E-mail inválido.")
	}
	if err := validatePassword(in.Password); err != nil {
		return "", err
	}
	hash, err := passhash.Hash(in.Password)
	if err != nil {
		return "", err
	}
	var id string
	err = s.DB.WithActor(ctx, a, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO people (name, email) VALUES ($1, $2) RETURNING id::text`, strings.TrimSpace(in.Name), email).Scan(&id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO panel_accounts (person_id, login_email, password_hash, is_admin) VALUES ($1, $2, $3, $4)`, id, email, hash, in.IsAdmin)
		if uniqueViolation(err) {
			return conflictError("Já existe um acesso ao painel com este e-mail.")
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, a, nil, "painel.acesso_criado", "person", id, map[string]any{"login": email, "is_admin": in.IsAdmin})
	})
	return id, err
}

// handlePutPanel cria ou altera o acesso ao painel de uma pessoa.
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
	in.LoginEmail = strings.ToLower(strings.TrimSpace(in.LoginEmail))
	active := in.Active == nil || *in.Active
	if !emailRe.MatchString(in.LoginEmail) {
		writeError(w, http.StatusBadRequest, "E-mail de login inválido.")
		return
	}
	if id == sess.UserID && (!in.IsAdmin || !active) {
		writeError(w, http.StatusBadRequest, "Você não pode remover o próprio acesso de administrador nem se desativar.")
		return
	}
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
		p, err := loadPerson(r.Context(), tx, id)
		if err != nil {
			return err
		}
		changes := map[string]any{}
		revoke := false
		if p.Panel == nil {
			if hash == "" {
				return validationError("Defina a senha inicial do painel.")
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO panel_accounts (person_id, login_email, password_hash, is_admin, active) VALUES ($1, $2, $3, $4, $5)`,
				id, in.LoginEmail, hash, in.IsAdmin, active)
			changes["login"], changes["is_admin"], changes["active"] = in.LoginEmail, in.IsAdmin, active
		} else {
			if in.LoginEmail != p.Panel.LoginEmail {
				changes["login"] = in.LoginEmail
			}
			if in.IsAdmin != p.Panel.IsAdmin {
				changes["is_admin"] = in.IsAdmin
			}
			if active != p.Panel.Active {
				changes["active"] = active
				revoke = !active
			}
			if hash != "" {
				changes["password"] = "alterada"
				revoke = true
			}
			if len(changes) == 0 {
				return nil
			}
			_, err = tx.Exec(r.Context(), `UPDATE panel_accounts SET login_email=$2, is_admin=$3, active=$4,
				password_hash = CASE WHEN $5 = '' THEN password_hash ELSE $5 END, updated_at=now() WHERE person_id=$1`,
				id, in.LoginEmail, in.IsAdmin, active, hash)
		}
		if uniqueViolation(err) {
			return conflictError("Já existe um acesso ao painel com este e-mail.")
		}
		if err != nil {
			return err
		}
		if revoke || changes["is_admin"] != nil {
			if _, err := tx.Exec(r.Context(), `DELETE FROM sessions WHERE person_id = $1`, id); err != nil {
				return err
			}
		}
		action := "painel.acesso_alterado"
		if p.Panel == nil {
			action = "painel.acesso_criado"
		}
		return audit(r.Context(), tx, sess.actor(r), nil, action, "person", id, changes)
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
		tag, err := tx.Exec(r.Context(), `DELETE FROM panel_accounts WHERE person_id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "painel.acesso_removido", "person", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

func (s *Server) handleSetPermissions(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	var in []Permission
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	seen := map[string]bool{}
	for _, p := range in {
		if !uuidRe.MatchString(p.CustomerID) || !modules[p.Module] || !levels[p.Level] {
			writeError(w, http.StatusBadRequest, "Permissão inválida: módulos aaa, servers, commands ou audit; níveis read ou write.")
			return
		}
		k := p.CustomerID + "/" + p.Module
		if seen[k] {
			writeError(w, http.StatusBadRequest, "Permissão repetida para o mesmo cliente e módulo.")
			return
		}
		seen[k] = true
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := loadPerson(r.Context(), tx, id)
		if err != nil {
			return err
		}
		if p.Panel == nil {
			return validationError("Esta pessoa não tem acesso ao painel.")
		}
		before := map[string]string{}
		for _, pm := range p.Panel.Permissions {
			before[pm.CustomerID+"/"+pm.Module] = pm.Level
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM panel_permissions WHERE person_id = $1`, id); err != nil {
			return err
		}
		after := map[string]string{}
		for _, pm := range in {
			if _, err := tx.Exec(r.Context(), `INSERT INTO panel_permissions (person_id, customer_id, module, level) VALUES ($1, $2, $3, $4)`, id, pm.CustomerID, pm.Module, pm.Level); err != nil {
				var pe *pgconn.PgError
				if errors.As(err, &pe) && pe.Code == "23503" {
					return validationError("Cliente inexistente na lista de permissões.")
				}
				return err
			}
			after[pm.CustomerID+"/"+pm.Module] = pm.Level
		}
		// Um evento por cliente afetado, para aparecer na auditoria daquele cliente.
		affected := map[string]map[string]any{}
		for k, lvl := range after {
			if before[k] != lvl {
				cid, mod, _ := strings.Cut(k, "/")
				if affected[cid] == nil {
					affected[cid] = map[string]any{}
				}
				affected[cid][mod] = lvl
			}
		}
		for k := range before {
			if _, ok := after[k]; !ok {
				cid, mod, _ := strings.Cut(k, "/")
				if affected[cid] == nil {
					affected[cid] = map[string]any{}
				}
				affected[cid][mod] = "sem acesso"
			}
		}
		for cid, ch := range affected {
			cid := cid
			if err := audit(r.Context(), tx, sess.actor(r), &cid, "painel.permissoes", "person", id, ch); err != nil {
				return err
			}
		}
		return nil
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
		return audit(r.Context(), tx, sess.actor(r), nil, "painel.mfa_redefinido", "person", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

// ---------- Acesso aos equipamentos ----------

type deviceInput struct {
	Username string  `json:"username"`
	Password *string `json:"password"`
	Active   *bool   `json:"active"` // padrão: true
}

// handlePutDevice cria ou altera a credencial de equipamento.
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
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	active := in.Active == nil || *in.Active
	if !usernameRe.MatchString(in.Username) {
		writeError(w, http.StatusBadRequest, "Usuário inválido: 3 a 32 caracteres, letras minúsculas, números, ponto, hífen ou sublinhado.")
		return
	}
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
		p, err := loadPerson(r.Context(), tx, id)
		if err != nil {
			return err
		}
		changes := map[string]any{}
		if p.Device == nil {
			if hash == "" {
				return validationError("Defina a senha dos equipamentos.")
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO device_accounts (person_id, username, password_hash, active) VALUES ($1, $2, $3, $4)`, id, in.Username, hash, active)
			changes["username"], changes["active"] = in.Username, active
		} else {
			if in.Username != p.Device.Username {
				changes["username"] = in.Username
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
				updated_at = now() WHERE person_id = $1`, id, in.Username, active, hash)
		}
		if uniqueViolation(err) {
			return conflictError("Este usuário de equipamento já está em uso.")
		}
		if err != nil {
			return err
		}
		action := "equipamentos.acesso_alterado"
		if p.Device == nil {
			action = "equipamentos.acesso_criado"
		}
		return audit(r.Context(), tx, sess.actor(r), nil, action, "person", id, changes)
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
		tag, err := tx.Exec(r.Context(), `DELETE FROM device_accounts WHERE person_id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "equipamentos.acesso_removido", "person", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}

// handleNewDeviceTOTP gera um TOTP novo para os equipamentos. O segredo só é mostrado nesta resposta;
// o anterior deixa de valer assim que a política for publicada para os Edges.
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
		err := tx.QueryRow(r.Context(), `UPDATE device_accounts SET totp_secret = $2, updated_at = now() WHERE person_id = $1 RETURNING username`, id, sealed).Scan(&username)
		if errors.Is(err, pgx.ErrNoRows) {
			return validationError("Crie o acesso aos equipamentos primeiro.")
		}
		if err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "equipamentos.totp_gerado", "person", id, nil)
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

func (s *Server) handleSetDeviceCustomers(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	var in []string
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	seen := map[string]bool{}
	for _, cid := range in {
		if !uuidRe.MatchString(cid) || seen[cid] {
			writeError(w, http.StatusBadRequest, "Lista de clientes inválida.")
			return
		}
		seen[cid] = true
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		p, err := loadPerson(r.Context(), tx, id)
		if err != nil {
			return err
		}
		if p.Device == nil {
			return validationError("Esta pessoa não tem acesso aos equipamentos.")
		}
		before := map[string]bool{}
		for _, c := range p.Device.Customers {
			before[c] = true
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM device_access WHERE person_id = $1`, id); err != nil {
			return err
		}
		for _, cid := range in {
			if _, err := tx.Exec(r.Context(), `INSERT INTO device_access (person_id, customer_id) VALUES ($1, $2)`, id, cid); err != nil {
				var pe *pgconn.PgError
				if errors.As(err, &pe) && pe.Code == "23503" {
					return validationError("Cliente inexistente.")
				}
				return err
			}
			if !before[cid] {
				cid := cid
				if err := audit(r.Context(), tx, sess.actor(r), &cid, "equipamentos.cliente_liberado", "person", id, map[string]any{"username": p.Device.Username}); err != nil {
					return err
				}
			}
		}
		for cid := range before {
			if !seen[cid] {
				cid := cid
				if err := audit(r.Context(), tx, sess.actor(r), &cid, "equipamentos.cliente_removido", "person", id, map[string]any{"username": p.Device.Username}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.respondPerson(w, r, id, http.StatusOK)
}
