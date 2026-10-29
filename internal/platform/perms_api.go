package platform

import (
	"net/http"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// customerIDs devolve os clientes visíveis (para conferir permissões "em algum cliente").
func (s *Server) visibleCustomerIDs(r *http.Request, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(r.Context(), `SELECT id::text FROM customers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, Catalog)
}

func (s *Server) requireSomewhere(r *http.Request, tx pgx.Tx, fn string) error {
	ids, err := s.visibleCustomerIDs(r, tx)
	if err != nil {
		return err
	}
	if !sessionFrom(r).canSomewhere(fn, ids) {
		return forbidden(fn)
	}
	return nil
}

func requireFullAdmin(r *http.Request) error {
	if !sessionFrom(r).IsAdmin {
		return forbiddenError("Só o Admin global gerencia tipos de acesso.")
	}
	return nil
}

// ---------- Tipos de acesso ----------

func (s *Server) handleListTypes(w http.ResponseWriter, r *http.Request) {
	var out []*AccessType
	err := s.DB.WithActor(r.Context(), sessionFrom(r).actor(r), func(tx pgx.Tx) error {
		if err := s.requireSomewhere(r, tx, "admin.people.view"); err != nil {
			return err
		}
		types, err := loadTypes(r.Context(), tx)
		if err != nil {
			return err
		}
		for _, t := range types {
			out = append(out, t)
		}
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin
		}
		return out[i].Name < out[j].Name
	})
	writeJSON(w, http.StatusOK, out)
}

type typeInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Scope       *string `json:"scope"`
	CopyFrom    *string `json:"copy_from"`
}

func (s *Server) handleCreateType(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if err := requireFullAdmin(r); err != nil {
		s.serverError(w, r, err)
		return
	}
	var in typeInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if in.Name == nil || len([]rune(strings.TrimSpace(*in.Name))) < 2 || in.Scope == nil || (*in.Scope != "global" && *in.Scope != "customer") {
		writeError(w, http.StatusBadRequest, "Informe o nome e o escopo (global ou customer).")
		return
	}
	var id string
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		desc := ""
		if in.Description != nil {
			desc = strings.TrimSpace(*in.Description)
		}
		err := tx.QueryRow(r.Context(), `INSERT INTO access_types (name, description, scope) VALUES ($1, $2, $3) RETURNING id::text`,
			strings.TrimSpace(*in.Name), desc, *in.Scope).Scan(&id)
		if uniqueViolation(err) {
			return conflictError("Já existe um tipo com esse nome.")
		}
		if err != nil {
			return err
		}
		if in.CopyFrom != nil && uuidRe.MatchString(*in.CopyFrom) {
			if _, err := tx.Exec(r.Context(), `INSERT INTO access_type_grants (type_id, function) SELECT $1, function FROM access_type_grants WHERE type_id = $2`, id, *in.CopyFrom); err != nil {
				return err
			}
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "permissoes.tipo_criado", "access_type", id, map[string]any{"name": *in.Name, "scope": *in.Scope})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) handleUpdateType(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if err := requireFullAdmin(r); err != nil {
		s.serverError(w, r, err)
		return
	}
	id, ok := personID(w, r)
	if !ok {
		return
	}
	var in typeInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE access_types SET name = coalesce(NULLIF(trim($2), ''), name), description = coalesce($3, description), updated_at = now() WHERE id = $1`,
			id, in.Name, in.Description)
		if uniqueViolation(err) {
			return conflictError("Já existe um tipo com esse nome.")
		}
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "permissoes.tipo_alterado", "access_type", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSetGrants(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if err := requireFullAdmin(r); err != nil {
		s.serverError(w, r, err)
		return
	}
	id, ok := personID(w, r)
	if !ok {
		return
	}
	var in []string
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, f := range in {
		if !ValidFunction(f) {
			writeError(w, http.StatusBadRequest, "Função inexistente: "+f)
			return
		}
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		var full bool
		var scope string
		if err := tx.QueryRow(r.Context(), `SELECT full_access, scope FROM access_types WHERE id = $1`, id).Scan(&full, &scope); err != nil {
			if err == pgx.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		if full {
			return validationError("O Admin global tem sempre todas as funções.")
		}
		if scope == "customer" {
			for _, f := range in {
				if catalogIndex[f].Platform {
					return validationError("\"" + catalogIndex[f].Label + "\" é função da plataforma e não vale em tipos por cliente.")
				}
			}
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM access_type_grants WHERE type_id = $1`, id); err != nil {
			return err
		}
		for _, f := range in {
			if _, err := tx.Exec(r.Context(), `INSERT INTO access_type_grants (type_id, function) VALUES ($1, $2) ON CONFLICT DO NOTHING`, id, f); err != nil {
				return err
			}
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "permissoes.tipo_funcoes", "access_type", id, map[string]any{"funcoes": len(in)})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteType(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if err := requireFullAdmin(r); err != nil {
		s.serverError(w, r, err)
		return
	}
	id, ok := personID(w, r)
	if !ok {
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		var builtin bool
		if err := tx.QueryRow(r.Context(), `SELECT builtin FROM access_types WHERE id = $1`, id).Scan(&builtin); err != nil {
			if err == pgx.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		if builtin {
			return validationError("Tipos prontos não podem ser excluídos.")
		}
		var inUse int
		if err := tx.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM panel_accounts WHERE access_type_id = $1) + (SELECT count(*) FROM panel_groups WHERE base_type_id = $1)`, id).Scan(&inUse); err != nil {
			return err
		}
		if inUse > 0 {
			return conflictError("Este tipo está em uso por pessoas ou grupos.")
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM access_types WHERE id = $1`, id); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), nil, "permissoes.tipo_excluido", "access_type", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------- Grupos ----------

func groupScope(g *PanelGroup) string {
	if g.CustomerID == nil {
		return ""
	}
	return *g.CustomerID
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	out := []*PanelGroup{}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		types, err := loadTypes(r.Context(), tx)
		if err != nil {
			return err
		}
		groups, err := loadGroups(r.Context(), tx, types)
		if err != nil {
			return err
		}
		for _, g := range groups {
			if sess.can("admin.people.view", groupScope(g)) {
				out = append(out, g)
			}
		}
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

type groupInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	CustomerID  *string `json:"customer_id"`
	BaseTypeID  *string `json:"base_type_id"`
}

// checkGroupBase confere a coerência do tipo base com o escopo do grupo e evita escalada.
func checkGroupBase(sess *Session, types map[string]*AccessType, customerID *string, baseID string) error {
	t := types[baseID]
	if t == nil {
		return validationError("Tipo base inexistente.")
	}
	if customerID != nil && t.Scope != "customer" {
		return validationError("Grupo de cliente precisa de tipo base de escopo por cliente.")
	}
	if (t.Scope == "global" || t.FullAccess) && !sess.IsAdmin {
		return forbiddenError("Só o Admin global cria grupos com tipo base global.")
	}
	return nil
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var in groupInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if in.Name == nil || len([]rune(strings.TrimSpace(*in.Name))) < 2 || in.BaseTypeID == nil {
		writeError(w, http.StatusBadRequest, "Informe o nome e o tipo base.")
		return
	}
	cid := optional(in.CustomerID)
	scope := ""
	if cid != nil {
		scope = *cid
	}
	if !sess.can("admin.people.edit", scope) {
		s.serverError(w, r, forbidden("admin.people.edit"))
		return
	}
	var id string
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		types, err := loadTypes(r.Context(), tx)
		if err != nil {
			return err
		}
		if err := checkGroupBase(sess, types, cid, *in.BaseTypeID); err != nil {
			return err
		}
		desc := ""
		if in.Description != nil {
			desc = strings.TrimSpace(*in.Description)
		}
		err = tx.QueryRow(r.Context(), `INSERT INTO panel_groups (name, customer_id, base_type_id, description) VALUES ($1, $2, $3, $4) RETURNING id::text`,
			strings.TrimSpace(*in.Name), cid, *in.BaseTypeID, desc).Scan(&id)
		if uniqueViolation(err) {
			return conflictError("Já existe um grupo com esse nome neste escopo.")
		}
		if err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), cid, "permissoes.grupo_criado", "panel_group", id, map[string]any{"name": *in.Name})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) loadGroupFor(r *http.Request, tx pgx.Tx, id, fn string) (*PanelGroup, map[string]*AccessType, error) {
	types, err := loadTypes(r.Context(), tx)
	if err != nil {
		return nil, nil, err
	}
	groups, err := loadGroups(r.Context(), tx, types)
	if err != nil {
		return nil, nil, err
	}
	g := groups[id]
	if g == nil || !sessionFrom(r).can("admin.people.view", groupScope(g)) {
		return nil, nil, ErrNotFound
	}
	if !sessionFrom(r).can(fn, groupScope(g)) {
		return nil, nil, forbidden(fn)
	}
	return g, types, nil
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	var in groupInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		g, types, err := s.loadGroupFor(r, tx, id, "admin.people.edit")
		if err != nil {
			return err
		}
		base := g.BaseTypeID
		if in.BaseTypeID != nil && *in.BaseTypeID != base {
			if err := checkGroupBase(sess, types, g.CustomerID, *in.BaseTypeID); err != nil {
				return err
			}
			base = *in.BaseTypeID
		}
		_, err = tx.Exec(r.Context(), `UPDATE panel_groups SET name = coalesce(NULLIF(trim($2), ''), name), description = coalesce($3, description), base_type_id = $4, updated_at = now() WHERE id = $1`,
			id, in.Name, in.Description, base)
		if uniqueViolation(err) {
			return conflictError("Já existe um grupo com esse nome neste escopo.")
		}
		if err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), g.CustomerID, "permissoes.grupo_alterado", "panel_group", id, nil)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleGroupOverrides(w http.ResponseWriter, r *http.Request) {
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
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		g, _, err := s.loadGroupFor(r, tx, id, "admin.people.edit")
		if err != nil {
			return err
		}
		for _, m := range g.Members {
			if m == sess.UserID && !sess.IsAdmin {
				return validationError("Você é membro deste grupo e não pode alterar as permissões dele.")
			}
		}
		for fn, eff := range in {
			if !ValidFunction(fn) || (eff != "allow" && eff != "deny") {
				return validationError("Exceção inválida: " + fn)
			}
			if eff == "allow" && !sess.can(fn, groupScope(g)) {
				return forbiddenError("Você não pode conceder \"" + catalogIndex[fn].Label + "\": você não tem essa função.")
			}
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM panel_group_overrides WHERE group_id = $1`, id); err != nil {
			return err
		}
		for fn, eff := range in {
			if _, err := tx.Exec(r.Context(), `INSERT INTO panel_group_overrides (group_id, function, effect) VALUES ($1, $2, $3)`, id, fn, eff); err != nil {
				return err
			}
		}
		return audit(r.Context(), tx, sess.actor(r), g.CustomerID, "permissoes.grupo_excecoes", "panel_group", id, map[string]any{"excecoes": len(in)})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		g, _, err := s.loadGroupFor(r, tx, id, "admin.people.edit")
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM panel_groups WHERE id = $1`, id); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), g.CustomerID, "permissoes.grupo_excluido", "panel_group", id, map[string]any{"name": g.Name})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------- Permissão efetiva e simulador ----------

type effectiveItem struct {
	Function string `json:"function"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason"`
}

// handleEffective devolve, para cada função, o resultado efetivo da pessoa num cliente ("" = plataforma).
func (s *Server) handleEffective(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := personID(w, r)
	if !ok {
		return
	}
	customer := r.URL.Query().Get("customer_id")
	if customer != "" && !uuidRe.MatchString(customer) {
		writeError(w, http.StatusBadRequest, "Cliente inválido.")
		return
	}
	var out []effectiveItem
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		if _, err := s.withPerson(r, tx, id, "admin.people.view"); err != nil {
			return err
		}
		subj, err := loadSubject(r.Context(), tx, id)
		if err != nil {
			return err
		}
		for _, f := range allFunctions() {
			d := subj.Can(f, customer)
			out = append(out, effectiveItem{Function: f, Allowed: d.Allowed, Reason: d.Reason})
		}
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type simulateInput struct {
	PersonID   string `json:"person_id"`
	CustomerID string `json:"customer_id"`
	Function   string `json:"function"`
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var in simulateInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if !uuidRe.MatchString(in.PersonID) || !ValidFunction(in.Function) || (in.CustomerID != "" && !uuidRe.MatchString(in.CustomerID)) {
		writeError(w, http.StatusBadRequest, "Informe pessoa, função e cliente válidos.")
		return
	}
	var d Decision
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		if _, err := s.withPerson(r, tx, in.PersonID, "admin.people.view"); err != nil {
			return err
		}
		subj, err := loadSubject(r.Context(), tx, in.PersonID)
		if err != nil {
			return err
		}
		d = subj.Can(in.Function, in.CustomerID)
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}
