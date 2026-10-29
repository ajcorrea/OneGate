package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// audit grava um evento na trilha de auditoria dentro da transação corrente.
func audit(ctx context.Context, tx pgx.Tx, a Actor, customerID *string, action, targetType, targetID string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	var actorID *string
	if a.UserID != "" {
		actorID = &a.UserID
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_log (actor_id, actor_label, customer_id, action, target_type, target_id, ip, details)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8)`,
		actorID, a.Label, customerID, action, targetType, targetID, a.IP, b)
	return err
}

// AuditEntry é um evento da trilha de auditoria.
type AuditEntry struct {
	ID           int64           `json:"id"`
	At           time.Time       `json:"at"`
	ActorLabel   string          `json:"actor"`
	CustomerID   *string         `json:"customer_id"`
	CustomerCode *string         `json:"customer_code"`
	Action       string          `json:"action"`
	TargetType   *string         `json:"target_type"`
	TargetID     *string         `json:"target_id"`
	IP           *string         `json:"ip"`
	Details      json.RawMessage `json:"details"`
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	customer := r.URL.Query().Get("customer_id")
	var out []AuditEntry
	err := s.DB.WithActor(r.Context(), sess.actor(r), func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
			SELECT a.id, a.at, a.actor_label, a.customer_id::text, c.code, a.action, a.target_type, a.target_id, a.ip, a.details
			FROM audit_log a LEFT JOIN customers c ON c.id = a.customer_id
			WHERE ($1 = '' OR a.customer_id::text = $1)
			ORDER BY a.at DESC, a.id DESC LIMIT $2`, customer, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e AuditEntry
			if err := rows.Scan(&e.ID, &e.At, &e.ActorLabel, &e.CustomerID, &e.CustomerCode, &e.Action, &e.TargetType, &e.TargetID, &e.IP, &e.Details); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if out == nil {
		out = []AuditEntry{}
	}
	writeJSON(w, http.StatusOK, out)
}
