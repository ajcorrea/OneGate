// Package platform é a API da nuvem ONE GATE: clientes, equipe, sessões e auditoria.
package platform

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB envolve o pool de conexões.
type DB struct {
	Pool *pgxpool.Pool
}

// Open conecta ao PostgreSQL.
func Open(ctx context.Context, url string) (*DB, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("banco: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("banco: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Close fecha o pool.
func (db *DB) Close() { db.Pool.Close() }

// Migrate aplica as migrações pendentes, em ordem, dentro de um lock exclusivo
// (várias instâncias da API podem subir ao mesmo tempo).
func (db *DB) Migrate(ctx context.Context) error {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	conn, err := db.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(7151979)`); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(7151979)`) //nolint:errcheck

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	for _, name := range names {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sql, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migração %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Actor identifica quem está agindo numa transação.
type Actor struct {
	UserID  string
	Label   string // nome legível para a auditoria (ex.: login ou "sistema")
	IsAdmin bool   // Admin global
	Global  bool   // enxerga todos os clientes
	IP      string
}

// System é o ator usado por processos internos (bootstrap, migrações de dados).
var System = Actor{Label: "sistema", IsAdmin: true}

// WithActor executa fn numa transação com a identidade do ator aplicada ao RLS.
func (db *DB) WithActor(ctx context.Context, a Actor, fn func(tx pgx.Tx) error) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT set_config('onegate.user_id', $1, true), set_config('onegate.is_admin', $2, true), set_config('onegate.global', $3, true)`,
		a.UserID, boolStr(a.IsAdmin), boolStr(a.IsAdmin || a.Global)); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ErrNotFound indica que o registro não existe (ou não é visível para o ator).
var ErrNotFound = errors.New("não encontrado")
