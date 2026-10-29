package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ajcorrea/onegate/internal/secretbox"
)

// Server é a API HTTP da plataforma.
type Server struct {
	DB  *DB
	Box *secretbox.Box
	Log *slog.Logger
	// SecureCookies deve ser true em produção (HTTPS). Em desenvolvimento local pode ser false.
	SecureCookies bool
	// TrustProxy faz a API usar X-Forwarded-For (só atrás de um proxy reverso confiável).
	TrustProxy bool
	// Static, se definido, serve o painel web compilado.
	Static http.Handler

	now     func() time.Time
	limiter *loginLimiter
}

// NewServer cria a API.
func NewServer(db *DB, box *secretbox.Box, log *slog.Logger) *Server {
	return &Server{DB: db, Box: box, Log: log, SecureCookies: true, now: time.Now, limiter: newLoginLimiter(5, 15*time.Minute)}
}

// Handler monta as rotas.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Autenticação
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/totp", s.pending(s.handleTOTP))
	mux.HandleFunc("POST /api/auth/recovery", s.pending(s.handleRecovery))
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/auth/me", s.authed(s.handleMe))

	// Clientes
	mux.HandleFunc("GET /api/customers", s.authed(s.handleListCustomers))
	mux.HandleFunc("POST /api/customers", s.platformFn("admin.customers.edit", s.handleCreateCustomer))
	mux.HandleFunc("GET /api/customers/{id}", s.authed(s.handleGetCustomer))
	mux.HandleFunc("PATCH /api/customers/{id}", s.platformFn("admin.customers.edit", s.handleUpdateCustomer))

	// Pessoas: acesso ao painel e acesso aos equipamentos são independentes.
	// A permissão é conferida no escopo da pessoa (domínio global = plataforma; domínio do cliente = cliente).
	mux.HandleFunc("GET /api/people", s.authed(s.handleListPeople))
	mux.HandleFunc("POST /api/people", s.authed(s.handleCreatePerson))
	mux.HandleFunc("PATCH /api/people/{id}", s.authed(s.handleUpdatePerson))
	mux.HandleFunc("PUT /api/people/{id}/panel", s.authed(s.handlePutPanel))
	mux.HandleFunc("DELETE /api/people/{id}/panel", s.authed(s.handleDeletePanel))
	mux.HandleFunc("PUT /api/people/{id}/panel/overrides", s.authed(s.handlePutOverrides))
	mux.HandleFunc("POST /api/people/{id}/panel/reset-totp", s.authed(s.handleResetPanelTOTP))
	mux.HandleFunc("GET /api/people/{id}/effective", s.authed(s.handleEffective))
	mux.HandleFunc("PUT /api/people/{id}/device", s.authed(s.handlePutDevice))
	mux.HandleFunc("DELETE /api/people/{id}/device", s.authed(s.handleDeleteDevice))
	mux.HandleFunc("POST /api/people/{id}/device/totp", s.authed(s.handleNewDeviceTOTP))

	// Permissões do painel: catálogo, tipos de acesso, grupos e simulador
	mux.HandleFunc("GET /api/permissions/catalog", s.authed(s.handleCatalog))
	mux.HandleFunc("POST /api/permissions/simulate", s.authed(s.handleSimulate))
	mux.HandleFunc("GET /api/access-types", s.authed(s.handleListTypes))
	mux.HandleFunc("POST /api/access-types", s.authed(s.handleCreateType))
	mux.HandleFunc("PATCH /api/access-types/{id}", s.authed(s.handleUpdateType))
	mux.HandleFunc("PUT /api/access-types/{id}/grants", s.authed(s.handleSetGrants))
	mux.HandleFunc("DELETE /api/access-types/{id}", s.authed(s.handleDeleteType))
	mux.HandleFunc("GET /api/panel-groups", s.authed(s.handleListGroups))
	mux.HandleFunc("POST /api/panel-groups", s.authed(s.handleCreateGroup))
	mux.HandleFunc("PATCH /api/panel-groups/{id}", s.authed(s.handleUpdateGroup))
	mux.HandleFunc("PUT /api/panel-groups/{id}/overrides", s.authed(s.handleGroupOverrides))
	mux.HandleFunc("DELETE /api/panel-groups/{id}", s.authed(s.handleDeleteGroup))

	// AAA: objetos, equipamentos, regras (rascunho e publicação) e simulador.
	// ?customer_id= define o escopo; sem ele, o escopo é global.
	mux.HandleFunc("GET /api/aaa/objects", s.authed(s.handleListObjects))
	mux.HandleFunc("POST /api/aaa/objects", s.authed(s.handleCreateObject))
	mux.HandleFunc("PATCH /api/aaa/objects/{id}", s.authed(s.handleUpdateObject))
	mux.HandleFunc("DELETE /api/aaa/objects/{id}", s.authed(s.handleDeleteObject))
	mux.HandleFunc("PUT /api/aaa/objects/{id}/members", s.authed(s.handleSetMembers))
	mux.HandleFunc("GET /api/aaa/devices", s.authed(s.handleListDevices))
	mux.HandleFunc("POST /api/aaa/devices", s.authed(s.handleCreateDevice))
	mux.HandleFunc("PATCH /api/aaa/devices/{id}", s.authed(s.handleUpdateDevice))
	mux.HandleFunc("DELETE /api/aaa/devices/{id}", s.authed(s.handleDeleteEquipment))
	mux.HandleFunc("POST /api/aaa/devices/{id}/rotate-secret", s.authed(s.handleRotateDeviceSecret))
	mux.HandleFunc("GET /api/aaa/rules", s.authed(s.handleGetRules))
	mux.HandleFunc("PUT /api/aaa/rules", s.authed(s.handlePutRules))
	mux.HandleFunc("POST /api/aaa/publish", s.authed(s.handlePublish))
	mux.HandleFunc("GET /api/aaa/search", s.authed(s.handleSearch))
	mux.HandleFunc("POST /api/aaa/simulate", s.authed(s.handleSimulateAAA))

	// Auditoria
	mux.HandleFunc("GET /api/audit", s.authed(s.handleListAudit))

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "Rota não encontrada.")
	})
	if s.Static != nil {
		mux.Handle("/", s.Static)
	}
	return s.securityHeaders(s.csrfGuard(mux))
}

// securityHeaders aplica cabeçalhos de segurança em todas as respostas.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'")
		if s.SecureCookies {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// csrfGuard exige JSON em toda requisição que altera dados. Junto com o cookie SameSite=Strict,
// isso impede que outro site dispare ações em nome do usuário (formulários não enviam JSON).
func (s *Server) csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if strings.HasPrefix(r.URL.Path, "/api/") {
				mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if mt != "application/json" {
					writeError(w, http.StatusUnsupportedMediaType, "Envie application/json.")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "Não encontrado.")
		return
	}
	var ve validationError
	if errors.As(err, &ve) {
		writeError(w, http.StatusBadRequest, ve.Error())
		return
	}
	var fe forbiddenError
	if errors.As(err, &fe) {
		writeError(w, http.StatusForbidden, fe.Error())
		return
	}
	var ce conflictError
	if errors.As(err, &ce) {
		writeError(w, http.StatusConflict, ce.Error())
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	s.Log.Error("erro interno", "rota", r.URL.Path, "erro", err)
	writeError(w, http.StatusInternalServerError, "Erro interno. Tente novamente.")
}

// decode lê o corpo JSON (máx. 64 KiB) recusando campos desconhecidos.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return validationError("JSON inválido: " + err.Error())
	}
	return nil
}

type validationError string

func (e validationError) Error() string { return string(e) }

type conflictError string

func (e conflictError) Error() string { return string(e) }
