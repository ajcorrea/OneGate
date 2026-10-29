package platform

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"golang.org/x/text/unicode/norm"

	"github.com/ajcorrea/onegate/internal/policy"
)

// aaaScope lê ?customer_id= ("" = escopo global).
func aaaScope(r *http.Request) (string, error) {
	cid := strings.TrimSpace(r.URL.Query().Get("customer_id"))
	if cid != "" && !uuidRe.MatchString(cid) {
		return "", validationError("Cliente inválido.")
	}
	return cid, nil
}

func (s *Server) requireIn(r *http.Request, scope string, fns ...string) error {
	sess := sessionFrom(r)
	for _, fn := range fns {
		if sess.can(fn, scope) {
			return nil
		}
	}
	return forbidden(fns[0])
}

// ---------- Objetos ----------

func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request) {
	cid, err := aaaScope(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.requireIn(r, cid, "aaa.rules.view", "aaa.devices.view", "aaa.users.manage"); err != nil {
		s.serverError(w, r, err)
		return
	}
	out := []*AAAObject{}
	err = s.DB.WithActor(r.Context(), sessionFrom(r).actor(r), func(tx pgx.Tx) error {
		objs, err := loadObjects(r.Context(), tx, cid)
		if err != nil {
			return err
		}
		for _, o := range objs {
			// No escopo do cliente, grupos de técnicos globais não aparecem (não podem ser usados ali).
			if cid != "" && o.Kind == kindUserGroup && o.CustomerID == nil {
				continue
			}
			if o.Members == nil && o.Kind == kindUserGroup {
				o.Members = []string{}
			}
			out = append(out, o)
		}
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type objectInput struct {
	CustomerID  *string          `json:"customer_id"`
	Kind        string           `json:"kind"`
	Name        *string          `json:"name"`
	Description *string          `json:"description"`
	Data        *json.RawMessage `json:"data"`
}

func cleanName(n *string) (string, error) {
	if n == nil {
		return "", validationError("Informe o nome.")
	}
	v := strings.Join(strings.Fields(*n), " ")
	if len([]rune(v)) < 2 || len([]rune(v)) > 60 || strings.ContainsAny(v, "@:") {
		return "", validationError("Nome entre 2 e 60 caracteres, sem @ nem :.")
	}
	return v, nil
}

// checkObjectName impede repetir o nome de um objeto do mesmo tipo que apareceria na mesma política.
func checkObjectName(ctx context.Context, tx pgx.Tx, kind, name, selfID string, cid *string) error {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM aaa_objects
		WHERE kind = $1 AND lower(name) = lower($2) AND id::text <> $3
		  AND (customer_id IS NULL OR $4::uuid IS NULL OR customer_id = $4)`, kind, name, selfID, cid).Scan(&n)
	if err != nil {
		return err
	}
	if n > 0 {
		return conflictError("Já existe um objeto desse tipo com esse nome (globais e do cliente aparecem juntos nas regras).")
	}
	return nil
}

func (s *Server) handleCreateObject(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var in objectInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	cid := optional(in.CustomerID)
	if cid != nil && !uuidRe.MatchString(*cid) {
		writeError(w, http.StatusBadRequest, "Cliente inválido.")
		return
	}
	if err := s.requireIn(r, scopeKey(cid), "aaa.rules.edit"); err != nil {
		s.serverError(w, r, err)
		return
	}
	name, err := cleanName(in.Name)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var raw json.RawMessage
	if in.Data != nil {
		raw = *in.Data
	}
	data, err := normalizeObjectData(in.Kind, raw)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	desc := ""
	if in.Description != nil {
		desc = strings.TrimSpace(*in.Description)
	}
	var id string
	err = s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		if err := checkObjectName(r.Context(), tx, in.Kind, name, "", cid); err != nil {
			return err
		}
		err := tx.QueryRow(r.Context(), `INSERT INTO aaa_objects (customer_id, kind, name, description, data) VALUES ($1, $2, $3, $4, $5) RETURNING id::text`,
			cid, in.Kind, name, desc, data).Scan(&id)
		if uniqueViolation(err) {
			return conflictError("Já existe um objeto desse tipo com esse nome.")
		}
		if err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), cid, "aaa.objeto_criado", in.Kind, id, map[string]any{"name": name, "data": json.RawMessage(data)})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// loadObjectFor carrega um objeto e confere a função no escopo dele.
func (s *Server) loadObjectFor(r *http.Request, tx pgx.Tx, fn string) (*AAAObject, error) {
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		return nil, ErrNotFound
	}
	o := &AAAObject{}
	err := tx.QueryRow(r.Context(), `SELECT id::text, customer_id::text, kind, name, description, data FROM aaa_objects WHERE id = $1`, id).
		Scan(&o.ID, &o.CustomerID, &o.Kind, &o.Name, &o.Description, &o.Data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.requireIn(r, scopeKey(o.CustomerID), fn); err != nil {
		return nil, err
	}
	return o, nil
}

func (s *Server) handleUpdateObject(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var in objectInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		o, err := s.loadObjectFor(r, tx, "aaa.rules.edit")
		if err != nil {
			return err
		}
		changes := map[string]any{}
		if in.Name != nil {
			name, err := cleanName(in.Name)
			if err != nil {
				return err
			}
			if err := checkObjectName(r.Context(), tx, o.Kind, name, o.ID, o.CustomerID); err != nil {
				return err
			}
			if name != o.Name {
				changes["name"] = map[string]string{"de": o.Name, "para": name}
			}
			o.Name = name
		}
		if in.Description != nil {
			o.Description = strings.TrimSpace(*in.Description)
		}
		if in.Data != nil {
			data, err := normalizeObjectData(o.Kind, *in.Data)
			if err != nil {
				return err
			}
			if string(data) != string(o.Data) {
				changes["data"] = map[string]json.RawMessage{"de": o.Data, "para": data}
			}
			o.Data = data
		}
		if _, err := tx.Exec(r.Context(), `UPDATE aaa_objects SET name = $2, description = $3, data = $4, updated_at = now() WHERE id = $1`,
			o.ID, o.Name, o.Description, o.Data); err != nil {
			if uniqueViolation(err) {
				return conflictError("Já existe um objeto desse tipo com esse nome.")
			}
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), o.CustomerID, "aaa.objeto_alterado", o.Kind, o.ID, changes)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// objectInUse lista as regras (rascunho ou última publicação) que usam o objeto. Apagar um objeto
// usado poderia estreitar uma regra de negar e liberar acesso sem ninguém publicar nada.
func objectInUse(ctx context.Context, tx pgx.Tx, id string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT r.name FROM aaa_rules r
		 WHERE EXISTS (SELECT 1 FROM unnest(r.who || r.where_refs || r.from_refs || r.when_refs || ARRAY[r.what]) x WHERE x LIKE '%:' || $1)
		UNION
		SELECT 'publicada: ' || coalesce(c.name, 'global') FROM (
		  SELECT DISTINCT ON (coalesce(customer_id, '00000000-0000-0000-0000-000000000000'::uuid)) customer_id, snapshot
		    FROM aaa_publications ORDER BY coalesce(customer_id, '00000000-0000-0000-0000-000000000000'::uuid), version DESC
		) p LEFT JOIN customers c ON c.id = p.customer_id
		 WHERE p.snapshot::text LIKE '%' || $1 || '%'`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		o, err := s.loadObjectFor(r, tx, "aaa.rules.edit")
		if err != nil {
			return err
		}
		used, err := objectInUse(r.Context(), tx, o.ID)
		if err != nil {
			return err
		}
		if len(used) > 0 {
			return conflictError("Objeto em uso: " + strings.Join(used, "; ") + ". Tire das regras e publique antes de apagar.")
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM aaa_objects WHERE id = $1`, o.ID); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), o.CustomerID, "aaa.objeto_apagado", o.Kind, o.ID, map[string]any{"name": o.Name})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetMembers(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var in struct {
		PersonIDs []string `json:"person_ids"`
	}
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		o, err := s.loadObjectFor(r, tx, "aaa.users.manage")
		if err != nil {
			return err
		}
		if o.Kind != kindUserGroup {
			return validationError("Só grupos de técnicos têm membros.")
		}
		seen := map[string]bool{}
		for _, pid := range in.PersonIDs {
			if !uuidRe.MatchString(pid) || seen[pid] {
				return validationError("Lista de pessoas inválida.")
			}
			seen[pid] = true
			var pc *string
			if err := tx.QueryRow(r.Context(), `SELECT customer_id::text FROM people WHERE id = $1`, pid).Scan(&pc); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return validationError("Pessoa inexistente.")
				}
				return err
			}
			if scopeKey(pc) != scopeKey(o.CustomerID) {
				return validationError("O grupo só aceita técnicos do mesmo domínio.")
			}
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM aaa_user_group_members WHERE group_id = $1`, o.ID); err != nil {
			return err
		}
		ids := make([]string, 0, len(seen))
		for pid := range seen {
			ids = append(ids, pid)
		}
		sort.Strings(ids)
		for _, pid := range ids {
			if _, err := tx.Exec(r.Context(), `INSERT INTO aaa_user_group_members (group_id, person_id) VALUES ($1, $2)`, o.ID, pid); err != nil {
				return err
			}
		}
		return audit(r.Context(), tx, sess.actor(r), o.CustomerID, "aaa.grupo_membros", o.Kind, o.ID, map[string]any{"name": o.Name, "membros": len(ids)})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Equipamentos ----------

type equipInput struct {
	CustomerID         string   `json:"customer_id"`
	Name               *string  `json:"name"`
	Address            *string  `json:"address"`
	Vendor             *string  `json:"vendor"`
	Model              *string  `json:"model"`
	MFA                *string  `json:"mfa"`
	CodeEntry          *string  `json:"code_entry"`
	TrustWindowSeconds *int     `json:"trust_window_seconds"`
	ClearTrustWindow   bool     `json:"clear_trust_window"`
	GroupIDs           []string `json:"group_ids"`
	Active             *bool    `json:"active"`
	// Secret permite informar a chave que já está configurada no equipamento (mínimo 16).
	Secret *string `json:"secret"`
}

var deviceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

const secretAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

func newDeviceSecret() (string, error) {
	b := make([]byte, 24)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(secretAlphabet))))
		if err != nil {
			return "", err
		}
		b[i] = secretAlphabet[n.Int64()]
	}
	return string(b), nil
}

func (in *equipInput) apply(d *aaaDevice) error {
	if in.Name != nil {
		d.Name = strings.TrimSpace(*in.Name)
		if !deviceNameRe.MatchString(d.Name) {
			return validationError("Nome do equipamento: letras, números, ponto, hífen e sublinhado (até 63).")
		}
	}
	if in.Address != nil {
		a, err := policy.NormalizeCIDR(strings.TrimSpace(*in.Address))
		if err != nil {
			return validationError("Endereço inválido: use o IP de origem do equipamento ou uma faixa.")
		}
		d.Address = strings.TrimSuffix(strings.TrimSuffix(a, "/32"), "/128")
	}
	if in.Vendor != nil {
		d.Vendor = strings.TrimSpace(*in.Vendor)
	}
	if in.Model != nil {
		d.Model = strings.TrimSpace(*in.Model)
	}
	if in.MFA != nil {
		d.MFA = *in.MFA
		if d.MFA != "inherit" && d.MFA != "off" && d.MFA != "totp" {
			return validationError("MFA: herdar, desligado ou TOTP.")
		}
	}
	if in.CodeEntry != nil {
		d.CodeEntry = *in.CodeEntry
		if d.CodeEntry != "prompt" && d.CodeEntry != "append" {
			return validationError("Entrada do código: segundo prompt ou junto da senha.")
		}
	}
	if in.ClearTrustWindow {
		d.TrustWindowSeconds = nil
	} else if in.TrustWindowSeconds != nil {
		if *in.TrustWindowSeconds < 0 || *in.TrustWindowSeconds > 86400 {
			return validationError("Janela de confiança entre 0 e 24 horas.")
		}
		d.TrustWindowSeconds = in.TrustWindowSeconds
	}
	if in.Active != nil {
		d.Active = *in.Active
	}
	if in.GroupIDs != nil {
		d.GroupIDs = in.GroupIDs
	}
	return nil
}

func (s *Server) saveDeviceGroups(ctx context.Context, tx pgx.Tx, d *aaaDevice) error {
	if _, err := tx.Exec(ctx, `DELETE FROM aaa_device_group_members WHERE device_id = $1`, d.ID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, g := range d.GroupIDs {
		if !uuidRe.MatchString(g) || seen[g] {
			return validationError("Grupo de equipamentos inválido.")
		}
		seen[g] = true
		var kind string
		var oc *string
		err := tx.QueryRow(ctx, `SELECT kind, customer_id::text FROM aaa_objects WHERE id = $1`, g).Scan(&kind, &oc)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (kind != kindDeviceGroup || (oc != nil && *oc != d.CustomerID))) {
			return validationError("Grupo de equipamentos inválido.")
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO aaa_device_group_members (device_id, group_id, position) VALUES ($1, $2, $3)`, d.ID, g, i); err != nil {
			return err
		}
	}
	return nil
}

func checkDeviceAddress(ctx context.Context, tx pgx.Tx, d *aaaDevice) error {
	var other string
	err := tx.QueryRow(ctx, `SELECT name FROM aaa_devices WHERE customer_id = $1 AND address = $2::cidr AND id::text <> $3 LIMIT 1`,
		d.CustomerID, d.Address, d.ID).Scan(&other)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return conflictError("O endereço já é do equipamento " + other + ".")
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	cid, err := aaaScope(r)
	if err == nil && cid == "" {
		err = validationError("Informe o cliente.")
	}
	if err == nil {
		err = s.requireIn(r, cid, "aaa.devices.view", "aaa.rules.view")
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	out := []*aaaDevice{}
	err = s.DB.WithActor(r.Context(), sessionFrom(r).actor(r), func(tx pgx.Tx) error {
		devs, err := loadDevices(r.Context(), tx, cid, "")
		if devs != nil {
			out = devs
		}
		return err
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var in equipInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if !uuidRe.MatchString(in.CustomerID) {
		writeError(w, http.StatusBadRequest, "Informe o cliente.")
		return
	}
	if in.Name == nil || in.Address == nil {
		writeError(w, http.StatusBadRequest, "Informe o nome e o endereço.")
		return
	}
	if err := s.requireIn(r, in.CustomerID, "aaa.devices.edit"); err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &aaaDevice{CustomerID: in.CustomerID, MFA: "inherit", CodeEntry: "prompt", Active: true, GroupIDs: []string{}}
	if err := in.apply(d); err != nil {
		s.serverError(w, r, err)
		return
	}
	if d.MFA == "off" && !sess.can("aaa.mfa.disable", in.CustomerID) {
		s.serverError(w, r, forbidden("aaa.mfa.disable"))
		return
	}
	secret, err := newDeviceSecret()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if in.Secret != nil && strings.TrimSpace(*in.Secret) != "" {
		secret = strings.TrimSpace(*in.Secret)
		if len(secret) < 16 {
			writeError(w, http.StatusBadRequest, "A chave compartilhada precisa de pelo menos 16 caracteres.")
			return
		}
	}
	err = s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		if err := checkDeviceAddress(r.Context(), tx, d); err != nil {
			return err
		}
		// O ID entra no contexto da cifra, então é gerado antes.
		if err := tx.QueryRow(r.Context(), `SELECT gen_random_uuid()::text`).Scan(&d.ID); err != nil {
			return err
		}
		sealed, err := s.Box.Seal(secret, deviceSecretCtx(d.ID))
		if err != nil {
			return err
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO aaa_devices (id, customer_id, name, address, vendor, model, mfa, code_entry, trust_window_seconds, secret, active)
			VALUES ($1, $2, $3, $4::cidr, $5, $6, $7, $8, $9, $10, $11)`,
			d.ID, d.CustomerID, d.Name, d.Address, d.Vendor, d.Model, d.MFA, d.CodeEntry, d.TrustWindowSeconds, sealed, d.Active)
		if uniqueViolation(err) {
			return conflictError("Já existe um equipamento com esse nome neste cliente.")
		}
		if err != nil {
			return err
		}
		if err := s.saveDeviceGroups(r.Context(), tx, d); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), &d.CustomerID, "aaa.equipamento_criado", "device", d.ID,
			map[string]any{"name": d.Name, "address": d.Address, "mfa": d.MFA})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": d.ID, "secret": secret})
}

func (s *Server) loadDeviceFor(r *http.Request, tx pgx.Tx, fn string) (*aaaDevice, error) {
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		return nil, ErrNotFound
	}
	var cid string
	err := tx.QueryRow(r.Context(), `SELECT customer_id::text FROM aaa_devices WHERE id = $1`, id).Scan(&cid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.requireIn(r, cid, fn); err != nil {
		return nil, err
	}
	devs, err := loadDevices(r.Context(), tx, cid, id)
	if err != nil || len(devs) == 0 {
		return nil, ErrNotFound
	}
	return devs[0], nil
}

func (s *Server) handleUpdateDevice(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var in equipInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if in.Secret != nil {
		writeError(w, http.StatusBadRequest, "Use a rotação de chave para trocar a chave do equipamento.")
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		d, err := s.loadDeviceFor(r, tx, "aaa.devices.edit")
		if err != nil {
			return err
		}
		before := *d
		if err := in.apply(d); err != nil {
			return err
		}
		if d.MFA == "off" && before.MFA != "off" && !sess.can("aaa.mfa.disable", d.CustomerID) {
			return forbidden("aaa.mfa.disable")
		}
		if err := checkDeviceAddress(r.Context(), tx, d); err != nil {
			return err
		}
		_, err = tx.Exec(r.Context(), `UPDATE aaa_devices SET name = $2, address = $3::cidr, vendor = $4, model = $5, mfa = $6, code_entry = $7,
			trust_window_seconds = $8, active = $9, updated_at = now() WHERE id = $1`,
			d.ID, d.Name, d.Address, d.Vendor, d.Model, d.MFA, d.CodeEntry, d.TrustWindowSeconds, d.Active)
		if uniqueViolation(err) {
			return conflictError("Já existe um equipamento com esse nome neste cliente.")
		}
		if err != nil {
			return err
		}
		if in.GroupIDs != nil {
			if err := s.saveDeviceGroups(r.Context(), tx, d); err != nil {
				return err
			}
		}
		changes := map[string]any{}
		if before.MFA != d.MFA {
			changes["mfa"] = map[string]string{"de": before.MFA, "para": d.MFA}
		}
		if before.Address != d.Address {
			changes["address"] = map[string]string{"de": before.Address, "para": d.Address}
		}
		if before.Active != d.Active {
			changes["active"] = d.Active
		}
		if before.Name != d.Name {
			changes["name"] = map[string]string{"de": before.Name, "para": d.Name}
		}
		return audit(r.Context(), tx, sess.actor(r), &d.CustomerID, "aaa.equipamento_alterado", "device", d.ID, changes)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRotateDeviceSecret(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	secret, err := newDeviceSecret()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	err = s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		d, err := s.loadDeviceFor(r, tx, "aaa.devices.secret")
		if err != nil {
			return err
		}
		sealed, err := s.Box.Seal(secret, deviceSecretCtx(d.ID))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `UPDATE aaa_devices SET secret = $2, updated_at = now() WHERE id = $1`, d.ID, sealed); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), &d.CustomerID, "aaa.equipamento_chave_rotacionada", "device", d.ID, map[string]any{"name": d.Name})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret})
}

func (s *Server) handleDeleteEquipment(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		d, err := s.loadDeviceFor(r, tx, "aaa.devices.edit")
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM aaa_devices WHERE id = $1`, d.ID); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), &d.CustomerID, "aaa.equipamento_apagado", "device", d.ID, map[string]any{"name": d.Name, "address": d.Address})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Regras ----------

type ruleScopeView struct {
	Rules       []AAARule    `json:"rules"`
	Publication *Publication `json:"publication"`
	Diff        []ruleDiff   `json:"diff"`
	Incomplete  []string     `json:"incomplete"`
	CanEdit     bool         `json:"can_edit"`
	CanPublish  bool         `json:"can_publish"`
}

func (s *Server) scopeView(r *http.Request, tx pgx.Tx, scope string, ix *refIndex, labels map[string]RefLabel) (*ruleScopeView, error) {
	sess := sessionFrom(r)
	rules, err := loadRules(r.Context(), tx, scope)
	if err != nil {
		return nil, err
	}
	pub, err := loadPublication(r.Context(), tx, scope)
	if err != nil {
		return nil, err
	}
	v := &ruleScopeView{Rules: rules, Publication: pub, Incomplete: []string{},
		CanEdit: sess.can("aaa.rules.edit", scope), CanPublish: sess.can("aaa.rules.publish", scope)}
	var published []AAARule
	if pub != nil {
		published = pub.Rules
	}
	v.Diff = diffRules(published, rules)
	for i := range rules {
		rr := &rules[i]
		if m := rr.missing(); len(m) > 0 {
			v.Incomplete = append(v.Incomplete, fmt.Sprintf("%s (sem %s)", rr.Name, strings.Join(m, ", ")))
		}
		for field, refs := range map[string][]string{"who": rr.Who, "where": rr.Where, "from": rr.From, "when": rr.When, "what": {rr.What}} {
			for _, ref := range refs {
				if ref != "" {
					labels[field+"|"+ref] = ix.label(field, ref)
				}
			}
		}
	}
	return v, nil
}

func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	cid, err := aaaScope(r)
	if err == nil {
		err = s.requireIn(r, cid, "aaa.rules.view")
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	out := map[string]any{}
	err = s.DB.WithActor(r.Context(), sessionFrom(r).actor(r), func(tx pgx.Tx) error {
		ix, err := s.loadRefIndex(r.Context(), tx, cid)
		if err != nil {
			return err
		}
		labels := map[string]RefLabel{}
		g, err := s.scopeView(r, tx, "", ix, labels)
		if err != nil {
			return err
		}
		out["global"] = g
		if cid != "" {
			c, err := s.scopeView(r, tx, cid, ix, labels)
			if err != nil {
				return err
			}
			out["customer"] = c
		}
		out["labels"] = labels
		out["domain"] = ix.domain
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type ruleInput struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Action string   `json:"action"`
	Who    []string `json:"who"`
	Where  []string `json:"where"`
	From   []string `json:"from"`
	What   string   `json:"what"`
	When   []string `json:"when"`
	MFA    string   `json:"mfa"`
}

func dedupe(xs []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// handlePutRules substitui o rascunho de um escopo (a lista completa, na ordem).
func (s *Server) handlePutRules(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	cid, err := aaaScope(r)
	if err == nil {
		err = s.requireIn(r, cid, "aaa.rules.edit")
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var in struct {
		Rules []ruleInput `json:"rules"`
	}
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(in.Rules) > 500 {
		writeError(w, http.StatusBadRequest, "Limite de 500 regras por escopo.")
		return
	}
	var saved []AAARule
	err = s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		ix, err := s.loadRefIndex(r.Context(), tx, cid)
		if err != nil {
			return err
		}
		current, err := loadRules(r.Context(), tx, cid)
		if err != nil {
			return err
		}
		byID := map[string]AAARule{}
		for _, c := range current {
			byID[c.ID] = c
		}
		keep := map[string]bool{}
		for i, ri := range in.Rules {
			rr := AAARule{ID: ri.ID, CustomerID: nullIfEmpty(cid), Name: strings.Join(strings.Fields(ri.Name), " "), Action: ri.Action,
				Who: dedupe(ri.Who), Where: dedupe(ri.Where), From: dedupe(ri.From), What: strings.TrimSpace(ri.What), When: dedupe(ri.When), MFA: ri.MFA}
			if rr.MFA == "" {
				rr.MFA = policy.RuleMFADevice
			}
			if l := len([]rune(rr.Name)); l < 2 || l > 80 {
				return validationError(fmt.Sprintf("Regra %d: nome entre 2 e 80 caracteres.", i+1))
			}
			if rr.Action != "allow" && rr.Action != "deny" {
				return validationError(fmt.Sprintf("Regra %q: ação deve ser permitir ou negar.", rr.Name))
			}
			if rr.MFA != policy.RuleMFATOTP && rr.MFA != policy.RuleMFADevice && rr.MFA != policy.RuleMFANone {
				return validationError(fmt.Sprintf("Regra %q: MFA inválido.", rr.Name))
			}
			if rr.Action == "deny" {
				rr.What = "" // regra de negar não tem perfil
			}
			if err := ix.checkRule(&rr, cid); err != nil {
				return err
			}
			prev, existed := byID[rr.ID]
			if rr.MFA == policy.RuleMFANone && (!existed || prev.MFA != policy.RuleMFANone) && !sess.can("aaa.mfa.disable", cid) {
				return forbiddenError(fmt.Sprintf("Regra %q: dispensar o MFA exige a função \"Desligar MFA de equipamento\".", rr.Name))
			}
			if !existed {
				if err := tx.QueryRow(r.Context(), `INSERT INTO aaa_rules (customer_id, position, name, action, who, where_refs, from_refs, what, when_refs, mfa)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id::text`,
					rr.CustomerID, i, rr.Name, rr.Action, rr.Who, rr.Where, rr.From, rr.What, rr.When, rr.MFA).Scan(&rr.ID); err != nil {
					return err
				}
			} else {
				if keep[rr.ID] {
					return validationError("Regra repetida na lista.")
				}
				if _, err := tx.Exec(r.Context(), `UPDATE aaa_rules SET position = $2, name = $3, action = $4, who = $5, where_refs = $6, from_refs = $7,
					what = $8, when_refs = $9, mfa = $10, updated_at = now() WHERE id = $1`,
					rr.ID, i, rr.Name, rr.Action, rr.Who, rr.Where, rr.From, rr.What, rr.When, rr.MFA); err != nil {
					return err
				}
			}
			keep[rr.ID] = true
			saved = append(saved, rr)
		}
		removed := 0
		for _, c := range current {
			if !keep[c.ID] {
				if _, err := tx.Exec(r.Context(), `DELETE FROM aaa_rules WHERE id = $1`, c.ID); err != nil {
					return err
				}
				removed++
			}
		}
		d := diffRules(current, saved)
		if len(d) == 0 {
			return nil
		}
		return audit(r.Context(), tx, sess.actor(r), nullIfEmpty(cid), "aaa.rascunho_salvo", "aaa_rules", cid,
			map[string]any{"regras": len(saved), "mudancas": d})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if saved == nil {
		saved = []AAARule{}
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	cid, err := aaaScope(r)
	if err == nil {
		err = s.requireIn(r, cid, "aaa.rules.publish")
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var in struct {
		Note string `json:"note"`
	}
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	var version int
	err = s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		// Uma publicação por vez em cada escopo.
		if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(7151980, hashtext($1))`, cid); err != nil {
			return err
		}
		rules, err := loadRules(r.Context(), tx, cid)
		if err != nil {
			return err
		}
		var incomplete []string
		for i := range rules {
			if m := rules[i].missing(); len(m) > 0 {
				incomplete = append(incomplete, fmt.Sprintf("%q (sem %s)", rules[i].Name, strings.Join(m, ", ")))
			}
		}
		if len(incomplete) > 0 {
			return validationError("Complete ou remova as regras incompletas antes de publicar: " + strings.Join(incomplete, "; ") + ".")
		}
		pub, err := loadPublication(r.Context(), tx, cid)
		if err != nil {
			return err
		}
		var published []AAARule
		if pub != nil {
			published, version = pub.Rules, pub.Version
		}
		diff := diffRules(published, rules)
		if pub != nil && len(diff) == 0 {
			return validationError("Nada para publicar: o rascunho é igual à versão publicada.")
		}
		// A política do cliente precisa compilar com o rascunho.
		if cid != "" {
			bp, err := s.buildPolicy(r.Context(), tx, cid, buildMode{Draft: true, Simulate: true})
			if err != nil {
				return err
			}
			if _, err := policy.Compile(bp.Policy); err != nil {
				return validationError("A política gerada não é válida: " + err.Error())
			}
		}
		version++
		snap, err := json.Marshal(map[string]any{"rules": rules})
		if err != nil {
			return err
		}
		var by *string
		if sess.UserID != "" {
			by = &sess.UserID
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO aaa_publications (customer_id, version, snapshot, note, published_by) VALUES ($1, $2, $3, $4, $5)`,
			nullIfEmpty(cid), version, snap, strings.TrimSpace(in.Note), by); err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), nullIfEmpty(cid), "aaa.regras_publicadas", "aaa_rules", cid,
			map[string]any{"versao": version, "nota": strings.TrimSpace(in.Note), "mudancas": diff})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"version": version})
}

// ---------- Busca (autocompletar) ----------

// fold normaliza para busca: minúsculas e sem acentos.
func fold(s string) string {
	t := norm.NFD.String(strings.ToLower(s))
	var b strings.Builder
	for _, r := range t {
		if !unicode.Is(unicode.Mn, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

type searchItem struct {
	Ref string `json:"ref"`
	RefLabel
}

// handleSearch sugere objetos para um campo da regra. Usuários só aparecem a partir de 3 letras
// (pode haver milhares); grupos e objetos aparecem logo.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	cid, err := aaaScope(r)
	if err == nil {
		err = s.requireIn(r, cid, "aaa.rules.view")
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	field := r.URL.Query().Get("field")
	q := fold(strings.TrimSpace(r.URL.Query().Get("q")))
	if _, ok := predefined[field]; !ok && field != "what" {
		writeError(w, http.StatusBadRequest, "Campo inválido.")
		return
	}
	out := []searchItem{}
	err = s.DB.WithActor(r.Context(), sessionFrom(r).actor(r), func(tx pgx.Tx) error {
		ix, err := s.loadRefIndex(r.Context(), tx, cid)
		if err != nil {
			return err
		}
		match := func(l RefLabel) bool {
			return q == "" || strings.Contains(fold(l.Label+" "+l.Sub), q)
		}
		add := func(ref string) {
			l := ix.label(field, ref)
			if !l.Missing && match(l) {
				out = append(out, searchItem{ref, l})
			}
		}
		pre := make([]string, 0, 2)
		for ref := range predefined[field] {
			pre = append(pre, ref)
		}
		sort.Strings(pre)
		for _, ref := range pre {
			add(ref)
		}
		inScope := func(o *AAAObject, allowGlobal bool) bool {
			if o.CustomerID == nil {
				return allowGlobal
			}
			return cid != "" && *o.CustomerID == cid
		}
		var objs []*AAAObject
		for _, o := range ix.objects {
			objs = append(objs, o)
		}
		sort.Slice(objs, func(i, j int) bool { return fold(objs[i].Name) < fold(objs[j].Name) })
		kindFor := map[string]string{"where": kindDeviceGroup, "from": kindNetwork, "what": kindProfile, "when": kindSchedule}
		prefix := map[string]string{"where": "group:", "from": "net:", "what": "profile:", "when": "schedule:"}
		switch field {
		case "who":
			for _, o := range objs {
				if o.Kind == kindUserGroup && scopeKey(o.CustomerID) == cid {
					add("group:" + o.ID)
				}
			}
			if len([]rune(q)) >= 3 {
				var ids []string
				for id, p := range ix.people {
					if scopeKey(p.CustomerID) == cid && p.Username != "" {
						ids = append(ids, id)
					}
				}
				sort.Slice(ids, func(i, j int) bool { return ix.people[ids[i]].Username < ix.people[ids[j]].Username })
				for _, id := range ids {
					add("user:" + id)
				}
			}
		default:
			for _, o := range objs {
				if o.Kind == kindFor[field] && inScope(o, true) {
					add(prefix[field] + o.ID)
				}
			}
			if field == "where" && cid != "" {
				var devs []*aaaDevice
				vendors := map[string]bool{}
				for _, d := range ix.devices {
					devs = append(devs, d)
					if d.Vendor != "" {
						vendors[d.Vendor] = true
					}
				}
				sort.Slice(devs, func(i, j int) bool { return devs[i].Name < devs[j].Name })
				var vs []string
				for v := range vendors {
					vs = append(vs, v)
				}
				sort.Strings(vs)
				for _, v := range vs {
					add("vendor:" + v)
				}
				for _, d := range devs {
					add("device:" + d.ID)
				}
			}
			if field == "from" && q != "" {
				if raw := strings.TrimSpace(r.URL.Query().Get("q")); policy.ValidateCIDR(raw) == nil {
					n, _ := policy.NormalizeCIDR(raw)
					out = append(out, searchItem{"cidr:" + n, RefLabel{Label: n, Sub: "usar esta faixa diretamente", Kind: "cidr"}})
				}
			}
		}
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(out) > 30 {
		out = out[:30]
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------- Simulador ----------

func (s *Server) handleSimulateAAA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CustomerID string `json:"customer_id"`
		Mode       string `json:"mode"` // draft | published
		User       string `json:"user"`
		DeviceID   string `json:"device_id"`
		Source     string `json:"source"`
		At         string `json:"at"` // "2006-01-02T15:04" no fuso do cliente; vazio = agora
		Command    string `json:"command"`
	}
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if !uuidRe.MatchString(in.CustomerID) || !uuidRe.MatchString(in.DeviceID) {
		writeError(w, http.StatusBadRequest, "Escolha o cliente e o equipamento.")
		return
	}
	if err := s.requireIn(r, in.CustomerID, "aaa.rules.view"); err != nil {
		s.serverError(w, r, err)
		return
	}
	var out map[string]any
	err := s.DB.WithActor(r.Context(), sessionFrom(r).actor(r), func(tx pgx.Tx) error {
		bp, err := s.buildPolicy(r.Context(), tx, in.CustomerID, buildMode{Draft: in.Mode != "published", Simulate: true})
		if err != nil {
			return err
		}
		eng, err := policy.Compile(bp.Policy)
		if err != nil {
			return validationError("A política gerada não é válida: " + err.Error())
		}
		devs, err := loadDevices(r.Context(), tx, in.CustomerID, in.DeviceID)
		if err != nil || len(devs) == 0 {
			return validationError("Equipamento inexistente.")
		}
		d, ok := eng.DeviceByName(devs[0].Name)
		if !ok {
			return validationError("Equipamento desativado não entra na política.")
		}
		at := time.Now()
		if in.At != "" {
			at, err = time.ParseInLocation("2006-01-02T15:04", in.At, eng.Location())
			if err != nil {
				return validationError("Data e hora inválidas.")
			}
		}
		req := policy.Request{User: in.User, Device: d, Source: strings.TrimSpace(in.Source), Time: at}
		res := eng.Evaluate(req)
		cmdChecked := false
		if strings.TrimSpace(in.Command) != "" && res.Allowed {
			res = eng.AuthorizeCommand(req, in.Command)
			cmdChecked = true
		}
		if res.Trail == nil {
			res.Trail = []policy.Step{}
		}
		out = map[string]any{
			"result":          res,
			"command_checked": cmdChecked,
			"at":              at.Format("Mon 02/01/2006 15:04 MST"),
			"warnings":        append(eng.Warnings(), bp.Dropped...),
			"versions":        map[string]int{"global": bp.Policy.GlobalRulesVersion, "customer": bp.Policy.CustomerRulesVersion},
		}
		return nil
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ExportPolicy gera o pacote assinado do cliente (usado pelo comando export-policy até o canal
// seguro com o Edge existir).
func (s *Server) ExportPolicy(ctx context.Context, customerCode string, sign func(*policy.Policy) ([]byte, error)) ([]byte, []string, error) {
	var out []byte
	var warnings []string
	err := s.DB.WithActor(ctx, System, func(tx pgx.Tx) error {
		var cid string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM customers WHERE upper(code) = upper($1)`, customerCode).Scan(&cid); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("cliente %q não encontrado", customerCode)
			}
			return err
		}
		bp, err := s.buildPolicy(ctx, tx, cid, buildMode{})
		if err != nil {
			return err
		}
		eng, err := policy.Compile(bp.Policy)
		if err != nil {
			return err
		}
		warnings = append(eng.Warnings(), bp.Dropped...)
		if out, err = sign(bp.Policy); err != nil {
			return err
		}
		return audit(ctx, tx, System, &cid, "aaa.politica_exportada", "customer", cid, map[string]any{
			"versao": bp.Policy.Version, "regras_globais": bp.Policy.GlobalRulesVersion, "regras_cliente": bp.Policy.CustomerRulesVersion,
			"equipamentos": len(bp.Policy.Devices), "tecnicos": len(bp.Policy.Users)})
	})
	return out, warnings, err
}
