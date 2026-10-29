// Package tacacs implementa o servidor TACACS+ do Edge sobre o motor de política.
//
// Cada conexão é associada a um equipamento pelo IP de origem; IPs desconhecidos são recusados
// antes de qualquer leitura. A chave compartilhada é a do próprio equipamento.
package tacacs

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nwaples/tacplus"

	"github.com/ajcorrea/onegate/internal/edgelog"
	"github.com/ajcorrea/onegate/internal/passhash"
	"github.com/ajcorrea/onegate/internal/policy"
	"github.com/ajcorrea/onegate/internal/totp"
)

// Mensagem genérica para o técnico: o motivo real só vai para a auditoria.
const deniedMsg = "Acesso negado."

// Server é o servidor TACACS+ do Edge.
type Server struct {
	engine  atomic.Pointer[policy.Engine]
	log     edgelog.Logger
	guard   totp.ReplayGuard
	trust   *trustStore
	limiter *failureLimiter
	now     func() time.Time
	// Errorf recebe erros de protocolo (chave errada, pacote inválido). Opcional.
	Errorf func(format string, args ...any)
}

// New cria o servidor com a política inicial.
func New(e *policy.Engine, log edgelog.Logger) *Server {
	s := &Server{
		log:     log,
		guard:   totp.NewMemoryGuard(),
		trust:   newTrustStore(),
		limiter: newFailureLimiter(5, 10*time.Minute),
		now:     time.Now,
	}
	s.engine.Store(e)
	return s
}

// SetPolicy troca a política em uso sem derrubar conexões.
func (s *Server) SetPolicy(e *policy.Engine) { s.engine.Store(e) }

// Policy devolve a política em uso.
func (s *Server) Policy() *policy.Engine { return s.engine.Load() }

// Serve atende conexões TACACS+ em l até ele ser fechado.
func (s *Server) Serve(l net.Listener) error {
	srv := &tacplus.Server{ServeConn: s.serveConn, Log: s.logErr}
	return srv.Serve(l)
}

func (s *Server) logErr(v ...any) {
	if s.Errorf != nil {
		s.Errorf("%v", v)
	}
}

func (s *Server) serveConn(nc net.Conn) {
	ap, err := netip.ParseAddrPort(nc.RemoteAddr().String())
	if err != nil {
		_ = nc.Close()
		return
	}
	ip := ap.Addr().Unmap()
	eng := s.engine.Load()
	dev, ok := eng.DeviceFor(ip)
	if !ok {
		s.log.Log(edgelog.Event{Kind: "conn", Customer: eng.Customer().Code, Policy: eng.Version(),
			DeviceIP: ip.String(), Result: "error", Reason: "equipamento não cadastrado"})
		_ = nc.Close()
		return
	}
	h := &tacplus.ServerConnHandler{
		Handler: &deviceHandler{s: s, ip: ip},
		ConnConfig: tacplus.ConnConfig{
			Mux:          true,
			Secret:       []byte(dev.Secret),
			IdleTimeout:  2 * time.Minute,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			Log: func(v ...any) {
				s.logErr(append([]any{"equipamento ", dev.Name, " (", ip.String(), "): "}, v...)...)
			},
		},
	}
	h.Serve(nc)
}

// deviceHandler atende os pedidos de uma conexão. A política é relida a cada pedido, então
// uma nova versão vale imediatamente, inclusive em conexões multiplexadas abertas.
type deviceHandler struct {
	s  *Server
	ip netip.Addr
}

func (h *deviceHandler) current() (*policy.Engine, *policy.Device) {
	eng := h.s.engine.Load()
	d, ok := eng.DeviceFor(h.ip)
	if !ok {
		return eng, nil
	}
	return eng, d
}

func (h *deviceHandler) event(eng *policy.Engine, d *policy.Device, kind string) edgelog.Event {
	ev := edgelog.Event{Time: h.s.now().UTC(), Kind: kind, Customer: eng.Customer().Code, Policy: eng.Version(), DeviceIP: h.ip.String()}
	if d != nil {
		ev.Device = d.Name
	}
	return ev
}

// HandleAuthenStart implementa a autenticação (login) com senha e TOTP.
func (h *deviceHandler) HandleAuthenStart(ctx context.Context, a *tacplus.AuthenStart, sess *tacplus.ServerSession) *tacplus.AuthenReply {
	eng, dev := h.current()
	ev := h.event(eng, dev, "authen")
	ev.RemAddr, ev.Port = a.RemAddr, a.Port
	fail := func(reason string) *tacplus.AuthenReply {
		ev.Result, ev.Reason = "fail", reason
		h.s.log.Log(ev)
		return &tacplus.AuthenReply{Status: tacplus.AuthenStatusFail, ServerMsg: deniedMsg}
	}
	if dev == nil {
		return fail("equipamento removido da política")
	}
	if a.Action != tacplus.AuthenActionLogin {
		return fail("ação de autenticação não suportada")
	}

	var user, pass string
	interactive := false
	switch a.AuthenType {
	case tacplus.AuthenTypePAP:
		user, pass = a.User, string(a.Data)
	case tacplus.AuthenTypeASCII:
		interactive = true
		user = a.User
		if user == "" {
			c, err := sess.GetUser(ctx, "Usuário: ")
			if err != nil || c == nil || c.Abort {
				return nil
			}
			user = c.Message
		}
		c, err := sess.GetPass(ctx, "Senha: ")
		if err != nil || c == nil || c.Abort {
			return nil
		}
		pass = c.Message
	default:
		return fail("tipo de autenticação não suportado (use ASCII ou PAP)")
	}
	ev.User = user

	now := h.s.now()
	limKey := strings.ToLower(user) + "\x00" + a.RemAddr
	if h.s.limiter.blocked(limKey, now) {
		return fail("bloqueado temporariamente por excesso de falhas")
	}
	u, ok := eng.ResolveUser(user)
	if !ok {
		passhash.VerifyDummy(pass)
		h.s.limiter.fail(limKey, now)
		return fail("usuário desconhecido")
	}
	user = u.Username
	ev.User = user
	if u.Disabled {
		return fail("usuário desativado")
	}
	sd := eng.Evaluate(policy.Request{User: user, Device: dev, Source: a.RemAddr, Time: now})
	ev.Rule = sd.Rule
	if !sd.Allowed {
		// Mesmo negado pela regra, gasta o tempo da verificação de senha: não revela se o usuário existe.
		passhash.VerifyDummy(pass)
		return fail(sd.Reason)
	}

	mfa := sd.MFA
	entry := mfa.Entry
	if !interactive {
		entry = policy.EntryAppend // PAP não permite segundo prompt
	}
	srcIP := ""
	if ip, ok := policy.ParseRemoteAddr(a.RemAddr); ok {
		srcIP = ip.String()
	}
	trusted := mfa.Required && h.s.trust.trusted(user, srcIP, now)

	code := ""
	pwOK := false
	switch {
	case mfa.Required && !trusted && entry == policy.EntryAppend:
		if len(pass) <= totp.Digits {
			h.s.limiter.fail(limKey, now)
			return fail("senha sem o código TOTP anexado")
		}
		pass, code = pass[:len(pass)-totp.Digits], pass[len(pass)-totp.Digits:]
		pwOK, _ = passhash.Verify(pass, u.PasswordHash)
	case trusted:
		// Dentro da janela o técnico pode digitar só a senha ou, por hábito, senha+código.
		pwOK, _ = passhash.Verify(pass, u.PasswordHash)
		if !pwOK && len(pass) > totp.Digits && digits(pass[len(pass)-totp.Digits:]) {
			pwOK, _ = passhash.Verify(pass[:len(pass)-totp.Digits], u.PasswordHash)
		}
	default:
		pwOK, _ = passhash.Verify(pass, u.PasswordHash)
	}
	if !pwOK {
		h.s.limiter.fail(limKey, now)
		return fail("senha incorreta")
	}

	ev.MFA = "none"
	if trusted {
		ev.MFA = "trusted"
	} else if mfa.Required {
		if u.TOTPSecret == "" {
			return fail("MFA exigido, mas o técnico não tem TOTP cadastrado")
		}
		if entry == policy.EntryPrompt {
			c, err := sess.GetData(ctx, "Código MFA: ", false)
			if err != nil || c == nil || c.Abort {
				return nil
			}
			code = c.Message
		}
		step, ok := totp.Validate(u.TOTPSecret, code, h.s.now(), totp.DefaultSkew)
		if !ok {
			h.s.limiter.fail(limKey, now)
			return fail("código TOTP inválido")
		}
		if !h.s.guard.Use(user, step) {
			h.s.limiter.fail(limKey, now)
			return fail("código TOTP já utilizado")
		}
		if mfa.TrustWindow > 0 {
			h.s.trust.grant(user, srcIP, now.Add(mfa.TrustWindow))
		}
		ev.MFA = "totp"
	}

	h.s.limiter.reset(limKey)
	ev.Result, ev.Priv = "pass", sd.PrivLevel
	h.s.log.Log(ev)
	return &tacplus.AuthenReply{Status: tacplus.AuthenStatusPass}
}

func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// args reúne os atributos de um pedido TACACS+ (formato "nome=valor" ou "nome*valor").
type args struct {
	service, cmd, taskID string
	cmdArgs              []string
}

func parseArgs(list []string) args {
	var a args
	for _, kv := range list {
		i := strings.IndexAny(kv, "=*")
		if i < 0 {
			continue
		}
		k, v := kv[:i], kv[i+1:]
		switch k {
		case "service":
			a.service = v
		case "cmd":
			a.cmd = v
		case "cmd-arg":
			if v != "<cr>" {
				a.cmdArgs = append(a.cmdArgs, v)
			}
		case "task_id":
			a.taskID = v
		}
	}
	return a
}

func (a args) command() string {
	if a.cmd == "" {
		return ""
	}
	return strings.TrimSpace(a.cmd + " " + strings.Join(a.cmdArgs, " "))
}

// HandleAuthorRequest autoriza a abertura de sessão (shell) e cada comando.
func (h *deviceHandler) HandleAuthorRequest(ctx context.Context, a *tacplus.AuthorRequest, sess *tacplus.ServerSession) *tacplus.AuthorResponse {
	eng, dev := h.current()
	ev := h.event(eng, dev, "author")
	ev.User, ev.RemAddr, ev.Port = a.User, a.RemAddr, a.Port
	ar := parseArgs(a.Arg)
	cmd := ar.command()
	ev.Command = policy.MaskSecrets(cmd)
	fail := func(reason, rule string) *tacplus.AuthorResponse {
		ev.Result, ev.Reason, ev.Rule = "fail", reason, rule
		h.s.log.Log(ev)
		return &tacplus.AuthorResponse{Status: tacplus.AuthorStatusFail, ServerMsg: "Comando não autorizado."}
	}
	if dev == nil {
		return fail("equipamento removido da política", "")
	}
	u, ok := eng.ResolveUser(a.User)
	if !ok || u.Disabled {
		return fail("usuário desconhecido ou desativado", "")
	}
	ev.User = u.Username
	req := policy.Request{User: u.Username, Device: dev, Source: a.RemAddr, Time: h.s.now()}

	if cmd == "" {
		d := eng.Evaluate(req)
		if !d.Allowed {
			return fail(d.Reason, d.Rule)
		}
		ev.Result, ev.Rule, ev.Priv, ev.Reason = "pass", d.Rule, d.PrivLevel, "início de sessão"
		h.s.log.Log(ev)
		resp := &tacplus.AuthorResponse{Status: tacplus.AuthorStatusPassAdd}
		if d.PrivLevel > 0 {
			resp.Arg = []string{"priv-lvl=" + strconv.Itoa(d.PrivLevel)}
		}
		return resp
	}

	d := eng.AuthorizeCommand(req, cmd)
	if !d.Allowed {
		return fail(d.Reason, d.Rule)
	}
	ev.Result, ev.Rule, ev.Reason = "pass", d.Rule, d.Reason
	h.s.log.Log(ev)
	return &tacplus.AuthorResponse{Status: tacplus.AuthorStatusPassAdd}
}

// HandleAcctRequest grava o accounting: início/fim de sessão e cada comando executado.
func (h *deviceHandler) HandleAcctRequest(ctx context.Context, a *tacplus.AcctRequest, sess *tacplus.ServerSession) *tacplus.AcctReply {
	eng, dev := h.current()
	ev := h.event(eng, dev, "acct")
	ev.User, ev.RemAddr, ev.Port = a.User, a.RemAddr, a.Port
	ar := parseArgs(a.Arg)
	ev.Command = policy.MaskSecrets(ar.command())
	ev.TaskID = ar.taskID
	ev.Priv = int(a.PrivLvl)
	switch {
	case a.Flags&tacplus.AcctFlagWatchdog != 0:
		ev.Result = "watchdog"
	case a.Flags&tacplus.AcctFlagStop != 0:
		ev.Result = "stop"
	case a.Flags&tacplus.AcctFlagStart != 0:
		ev.Result = "start"
	default:
		ev.Result = "unknown"
	}
	h.s.log.Log(ev)
	return &tacplus.AcctReply{Status: tacplus.AcctStatusSuccess}
}
