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
)

// StaffUser é um membro da equipe da ON TELECOM.
type StaffUser struct {
	ID          string      `json:"id"`
	Email       string      `json:"email"`
	Username    string      `json:"username"`
	Name        string      `json:"name"`
	IsAdmin     bool        `json:"is_admin"`
	Active      bool        `json:"active"`
	TOTPEnabled bool        `json:"totp_enabled"`
	LastLoginAt *time.Time  `json:"last_login_at"`
	CreatedAt   time.Time   `json:"created_at"`
	Roles       []StaffRole `json:"roles"`
}

// StaffRole é o papel do técnico num cliente.
type StaffRole struct {
	CustomerID string `json:"customer_id"`
	Role       string `json:"role"`
}

var (
	emailRe    = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)
	roles      = map[string]bool{"viewer": true, "operator": true, "admin": true}
)

const minPasswordLen = 12

// validatePassword aplica a política mínima de senha da equipe.
func validatePassword(pw string) error {
	if len([]rune(pw)) < minPasswordLen {
		return validationError("A senha precisa de pelo menos 12 caracteres.")
	}
	return nil
}

const staffCols = `id::text, email, username, name, is_admin, active, totp_enabled, last_login_at, created_at`

func scanStaff(row pgx.Row) (StaffUser, error) {
	var u StaffUser
	err := row.Scan(&u.ID, &u.Email, &u.Username, &u.Name, &u.IsAdmin, &u.Active, &u.TOTPEnabled, &u.LastLoginAt, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	u.Roles = []StaffRole{}
	return u, err
}

func loadRoles(ctx context.Context, tx pgx.Tx, users []StaffUser) error {
	idx := map[string]int{}
	for i := range users {
		idx[users[i].ID] = i
	}
	rows, err := tx.Query(ctx, `SELECT user_id::text, customer_id::text, role FROM staff_customer_roles ORDER BY user_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var uid string
		var r StaffRole
		if err := rows.Scan(&uid, &r.CustomerID, &r.Role); err != nil {
			return err
		}
		if i, ok := idx[uid]; ok {
			users[i].Roles = append(users[i].Roles, r)
		}
	}
	return rows.Err()
}

func (s *Server) handleListStaff(w http.ResponseWriter, r *http.Request) {
	out := []StaffUser{}
	err := s.DB.WithActor(r.Context(), sessionFrom(r).actor(r), func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT `+staffCols+` FROM staff_users ORDER BY name`)
		if err != nil {
			return err
		}
		for rows.Next() {
			u, err := scanStaff(rows)
			if err != nil {
				rows.Close()
				return err
			}
			out = append(out, u)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		return loadRoles(r.Context(), tx, out)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// NewStaff são os dados de um novo membro da equipe.
type NewStaff struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
}

// CreateStaff cria um membro da equipe (usado pela API e pelo bootstrap do primeiro administrador).
func (s *Server) CreateStaff(ctx context.Context, a Actor, in NewStaff) (StaffUser, error) {
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	in.Name = strings.TrimSpace(in.Name)
	if !emailRe.MatchString(in.Email) {
		return StaffUser{}, validationError("E-mail inválido.")
	}
	if !usernameRe.MatchString(in.Username) {
		return StaffUser{}, validationError("Usuário inválido: 3 a 32 caracteres, letras minúsculas, números, ponto, hífen ou sublinhado.")
	}
	if len([]rune(in.Name)) < 2 {
		return StaffUser{}, validationError("Informe o nome.")
	}
	if err := validatePassword(in.Password); err != nil {
		return StaffUser{}, err
	}
	hash, err := passhash.Hash(in.Password)
	if err != nil {
		return StaffUser{}, err
	}
	var u StaffUser
	err = s.DB.WithActor(ctx, a, func(tx pgx.Tx) error {
		var err error
		u, err = scanStaff(tx.QueryRow(ctx, `INSERT INTO staff_users (email, username, name, password_hash, is_admin)
			VALUES ($1, $2, $3, $4, $5) RETURNING `+staffCols, in.Email, in.Username, in.Name, hash, in.IsAdmin))
		if uniqueViolation(err) {
			return conflictError("E-mail ou usuário já cadastrado.")
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, a, nil, "equipe.criado", "staff_user", u.ID,
			map[string]any{"email": u.Email, "username": u.Username, "is_admin": u.IsAdmin})
	})
	return u, err
}

func (s *Server) handleCreateStaff(w http.ResponseWriter, r *http.Request) {
	var in NewStaff
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	u, err := s.CreateStaff(r.Context(), sessionFrom(r).actor(r), in)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

type updateStaffInput struct {
	Name     *string `json:"name"`
	IsAdmin  *bool   `json:"is_admin"`
	Active   *bool   `json:"active"`
	Password *string `json:"password"`
}

func (s *Server) handleUpdateStaff(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		writeError(w, http.StatusNotFound, "Não encontrado.")
		return
	}
	var in updateStaffInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if id == sess.UserID && ((in.IsAdmin != nil && !*in.IsAdmin) || (in.Active != nil && !*in.Active)) {
		writeError(w, http.StatusBadRequest, "Você não pode remover o próprio acesso de administrador nem se desativar.")
		return
	}
	var u StaffUser
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		var err error
		u, err = scanStaff(tx.QueryRow(r.Context(), `SELECT `+staffCols+` FROM staff_users WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		changes := map[string]any{}
		if in.Name != nil {
			v := strings.TrimSpace(*in.Name)
			if len([]rune(v)) < 2 {
				return validationError("Informe o nome.")
			}
			u.Name, changes["name"] = v, v
		}
		if in.IsAdmin != nil && *in.IsAdmin != u.IsAdmin {
			u.IsAdmin, changes["is_admin"] = *in.IsAdmin, *in.IsAdmin
		}
		revoke := false
		if in.Active != nil && *in.Active != u.Active {
			u.Active, changes["active"] = *in.Active, *in.Active
			revoke = !u.Active
		}
		hash := ""
		if in.Password != nil {
			if err := validatePassword(*in.Password); err != nil {
				return err
			}
			if hash, err = passhash.Hash(*in.Password); err != nil {
				return err
			}
			changes["password"] = "alterada"
			revoke = true
		}
		if len(changes) == 0 {
			return nil
		}
		if _, err := tx.Exec(r.Context(), `UPDATE staff_users SET name=$2, is_admin=$3, active=$4,
			password_hash = CASE WHEN $5 = '' THEN password_hash ELSE $5 END, updated_at = now() WHERE id = $1`,
			id, u.Name, u.IsAdmin, u.Active, hash); err != nil {
			return err
		}
		if revoke {
			if _, err := tx.Exec(r.Context(), `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
				return err
			}
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "equipe.alterado", "staff_user", id, changes)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleSetRoles(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		writeError(w, http.StatusNotFound, "Não encontrado.")
		return
	}
	var in []StaffRole
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	seen := map[string]bool{}
	for _, ro := range in {
		if !uuidRe.MatchString(ro.CustomerID) || !roles[ro.Role] {
			writeError(w, http.StatusBadRequest, "Papel inválido: use viewer, operator ou admin.")
			return
		}
		if seen[ro.CustomerID] {
			writeError(w, http.StatusBadRequest, "Cliente repetido na lista de papéis.")
			return
		}
		seen[ro.CustomerID] = true
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		if _, err := scanStaff(tx.QueryRow(r.Context(), `SELECT `+staffCols+` FROM staff_users WHERE id = $1`, id)); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM staff_customer_roles WHERE user_id = $1`, id); err != nil {
			return err
		}
		for _, ro := range in {
			if _, err := tx.Exec(r.Context(), `INSERT INTO staff_customer_roles (user_id, customer_id, role) VALUES ($1, $2, $3)`, id, ro.CustomerID, ro.Role); err != nil {
				var pe *pgconn.PgError
				if errors.As(err, &pe) && pe.Code == "23503" {
					return validationError("Cliente inexistente na lista de papéis.")
				}
				return err
			}
			cid := ro.CustomerID
			if err := audit(r.Context(), tx, sess.actor(r), &cid, "equipe.papel", "staff_user", id, map[string]any{"role": ro.Role}); err != nil {
				return err
			}
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "equipe.papeis_definidos", "staff_user", id, map[string]any{"total": len(in)})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, in)
}

// handleResetTOTP apaga o TOTP do técnico (celular perdido). No próximo login ele cadastra de novo.
func (s *Server) handleResetTOTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		writeError(w, http.StatusNotFound, "Não encontrado.")
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE staff_users SET totp_secret = NULL, totp_enabled = false, totp_last_step = NULL, updated_at = now() WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM recovery_codes WHERE user_id = $1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "mfa.redefinido", "staff_user", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
