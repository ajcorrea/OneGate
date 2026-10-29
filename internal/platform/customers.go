package platform

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Customer é um cliente da ON TELECOM (provedor ou empresa de outro segmento).
type Customer struct {
	ID                 string    `json:"id"`
	Code               string    `json:"code"`
	Name               string    `json:"name"`
	Domain             string    `json:"domain"`
	Segment            string    `json:"segment"`
	Color              string    `json:"color"`
	MFA                string    `json:"mfa"`
	TrustWindowSeconds int       `json:"trust_window_seconds"`
	Active             bool      `json:"active"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

const customerCols = `id::text, code, name, domain, segment, color, mfa, trust_window_seconds, active, created_at, updated_at`

func scanCustomer(row pgx.Row) (Customer, error) {
	var c Customer
	err := row.Scan(&c.ID, &c.Code, &c.Name, &c.Domain, &c.Segment, &c.Color, &c.MFA, &c.TrustWindowSeconds, &c.Active, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

var (
	codeRe   = regexp.MustCompile(`^[A-Z0-9]{3}$`)
	colorRe  = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)
	domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// Segmentos aceitos. "outro" cobre qualquer segmento não listado.
var segments = map[string]bool{"provedor": true, "empresa": true, "saude": true, "educacao": true, "governo": true, "industria": true, "logistica": true, "varejo": true, "outro": true}

func (s *Server) handleListCustomers(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	out := []Customer{}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT `+customerCols+` FROM customers ORDER BY code`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanCustomer(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetCustomer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		writeError(w, http.StatusNotFound, "Não encontrado.")
		return
	}
	var c Customer
	err := s.DB.WithActor(r.Context(), sessionFrom(r).actor(r), func(tx pgx.Tx) error {
		var err error
		c, err = scanCustomer(tx.QueryRow(r.Context(), `SELECT `+customerCols+` FROM customers WHERE id = $1`, id))
		return err
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

type customerInput struct {
	Code               *string `json:"code"`
	Name               *string `json:"name"`
	Domain             *string `json:"domain"`
	Segment            *string `json:"segment"`
	Color              *string `json:"color"`
	MFA                *string `json:"mfa"`
	TrustWindowSeconds *int    `json:"trust_window_seconds"`
	Active             *bool   `json:"active"`
}

// apply valida e aplica a entrada sobre c. Devolve as mudanças para a auditoria.
func (in customerInput) apply(c *Customer) (map[string]any, error) {
	changes := map[string]any{}
	if in.Code != nil {
		v := strings.ToUpper(strings.TrimSpace(*in.Code))
		if !codeRe.MatchString(v) {
			return nil, validationError("O código deve ter 3 letras ou números (ex.: NSF).")
		}
		if v != c.Code {
			changes["code"] = v
		}
		c.Code = v
	}
	if in.Name != nil {
		v := strings.TrimSpace(*in.Name)
		if len([]rune(v)) < 2 || len([]rune(v)) > 120 {
			return nil, validationError("Informe o nome do cliente (2 a 120 caracteres).")
		}
		if v != c.Name {
			changes["name"] = v
		}
		c.Name = v
	}
	if in.Domain != nil {
		v := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(*in.Domain), "@")))
		if !domainRe.MatchString(v) {
			return nil, validationError("Domínio inválido (ex.: netsulfibra.com.br).")
		}
		if v == GlobalDomain {
			return nil, validationError("O domínio " + GlobalDomain + " é reservado para os acessos globais.")
		}
		if c.Domain != "" && v != c.Domain {
			return nil, validationError("O domínio do cliente não pode ser trocado depois de criado: ele faz parte do login das pessoas.")
		}
		c.Domain = v
	}
	if in.Segment != nil {
		v := strings.ToLower(strings.TrimSpace(*in.Segment))
		if !segments[v] {
			return nil, validationError("Segmento inválido.")
		}
		if v != c.Segment {
			changes["segment"] = v
		}
		c.Segment = v
	}
	if in.Color != nil {
		v := strings.ToUpper(strings.TrimSpace(*in.Color))
		if !colorRe.MatchString(v) {
			return nil, validationError("Cor inválida. Use o formato #RRGGBB.")
		}
		if v != c.Color {
			changes["color"] = v
		}
		c.Color = v
	}
	if in.MFA != nil {
		v := *in.MFA
		if v != "off" && v != "totp" {
			return nil, validationError("MFA padrão deve ser \"off\" ou \"totp\".")
		}
		if v != c.MFA {
			changes["mfa"] = v
		}
		c.MFA = v
	}
	if in.TrustWindowSeconds != nil {
		v := *in.TrustWindowSeconds
		if v < 0 || v > 86400 {
			return nil, validationError("Janela de confiança entre 0 e 24 horas.")
		}
		if v != c.TrustWindowSeconds {
			changes["trust_window_seconds"] = v
		}
		c.TrustWindowSeconds = v
	}
	if in.Active != nil {
		if *in.Active != c.Active {
			changes["active"] = *in.Active
		}
		c.Active = *in.Active
	}
	return changes, nil
}

func uniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (s *Server) handleCreateCustomer(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var in customerInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	if in.Code == nil || in.Name == nil || in.Color == nil || in.Domain == nil {
		writeError(w, http.StatusBadRequest, "Código, nome, domínio e cor são obrigatórios.")
		return
	}
	c := Customer{Segment: "provedor", MFA: "totp", TrustWindowSeconds: 3600, Active: true}
	if _, err := in.apply(&c); err != nil {
		s.serverError(w, r, err)
		return
	}
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		var err error
		c, err = scanCustomer(tx.QueryRow(r.Context(), `
			INSERT INTO customers (code, name, domain, segment, color, mfa, trust_window_seconds, active)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING `+customerCols,
			c.Code, c.Name, c.Domain, c.Segment, c.Color, c.MFA, c.TrustWindowSeconds, c.Active))
		if uniqueViolation(err) {
			return conflictError("Já existe um cliente com o código " + c.Code + " ou o domínio " + c.Domain + ".")
		}
		if err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), &c.ID, "cliente.criado", "customer", c.ID,
			map[string]any{"code": c.Code, "name": c.Name, "domain": c.Domain, "segment": c.Segment, "mfa": c.MFA})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) handleUpdateCustomer(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		writeError(w, http.StatusNotFound, "Não encontrado.")
		return
	}
	var in customerInput
	if err := decode(r, &in); err != nil {
		s.serverError(w, r, err)
		return
	}
	var c Customer
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		var err error
		c, err = scanCustomer(tx.QueryRow(r.Context(), `SELECT `+customerCols+` FROM customers WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		changes, err := in.apply(&c)
		if err != nil {
			return err
		}
		if len(changes) == 0 {
			return nil
		}
		c, err = scanCustomer(tx.QueryRow(r.Context(), `
			UPDATE customers SET code=$2, name=$3, segment=$4, color=$5, mfa=$6, trust_window_seconds=$7, active=$8, updated_at=now()
			WHERE id = $1 RETURNING `+customerCols,
			id, c.Code, c.Name, c.Segment, c.Color, c.MFA, c.TrustWindowSeconds, c.Active))
		if uniqueViolation(err) {
			return conflictError("Já existe um cliente com o código " + c.Code + ".")
		}
		if err != nil {
			return err
		}
		return audit(r.Context(), tx, sess.actor(r), &c.ID, "cliente.alterado", "customer", c.ID, changes)
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}
