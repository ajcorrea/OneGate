// Comando onegate-edge: o Edge instalado na rede do cliente.
//
//	onegate-edge serve --policy policy.json --listen :49 --events eventos.jsonl
//	onegate-edge check-policy --policy policy.json
//	onegate-edge simulate --policy policy.json --user pedro.lima --device bng-01 --from 172.16.50.8 --cmd "display version"
//	onegate-edge hash-password
//	onegate-edge totp-secret --user alexandre.c --customer NSF
//	onegate-edge test-login --server 10.0.0.250:49 --secret CHAVE --user alexandre.c
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nwaples/tacplus"
	"golang.org/x/term"

	"github.com/ajcorrea/onegate/internal/edgelog"
	"github.com/ajcorrea/onegate/internal/passhash"
	"github.com/ajcorrea/onegate/internal/policy"
	"github.com/ajcorrea/onegate/internal/tacacs"
	"github.com/ajcorrea/onegate/internal/totp"
)

var version = "dev"

// stdin é compartilhado para não perder linhas já lidas para o buffer.
var stdin = bufio.NewReader(os.Stdin)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "check-policy":
		err = checkPolicy(os.Args[2:])
	case "simulate":
		err = simulate(os.Args[2:])
	case "hash-password":
		err = hashPassword()
	case "totp-secret":
		err = totpSecret(os.Args[2:])
	case "test-login":
		err = testLogin(os.Args[2:])
	case "version":
		fmt.Println("onegate-edge", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ONE GATE Edge

Uso:
  onegate-edge serve         --policy ARQ [--listen :49] [--events ARQ] [--pubkey CHAVE]
  onegate-edge check-policy  --policy ARQ
  onegate-edge simulate      --policy ARQ --user USUARIO --device NOME|IP --from IP [--at "AAAA-MM-DD HH:MM"] [--cmd COMANDO]
  onegate-edge hash-password
  onegate-edge totp-secret   --user USUARIO [--customer COD]
  onegate-edge test-login    --server HOST:49 --secret CHAVE --user USUARIO [--pap] [--rem-addr IP]
  onegate-edge version
`)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	policyPath := fs.String("policy", "/etc/onegate/policy.json", "arquivo da política")
	listen := fs.String("listen", ":49", "endereço TACACS+")
	events := fs.String("events", "/var/lib/onegate/events.jsonl", "arquivo de eventos (auditoria/accounting)")
	pubkey := fs.String("pubkey", os.Getenv("ONEGATE_POLICY_PUBKEY"), "chave pública da nuvem (base64); com ela, só aceita política assinada")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	load := func() (*policy.Engine, error) { return policy.Load(*policyPath) }
	if *pubkey != "" {
		pub, err := policy.ParsePublicKey(*pubkey)
		if err != nil {
			return err
		}
		load = func() (*policy.Engine, error) { return policy.LoadSigned(*policyPath, pub) }
	} else {
		logger.Warn("sem --pubkey: aceitando política sem assinatura (só para laboratório)")
	}
	eng, err := load()
	if err != nil {
		return err
	}
	for _, w := range eng.Warnings() {
		logger.Warn("política", "aviso", w)
	}
	ev, err := edgelog.OpenFile(*events)
	if err != nil {
		return fmt.Errorf("abrir arquivo de eventos: %w", err)
	}
	defer ev.Close()

	srv := tacacs.New(eng, ev)
	srv.Errorf = func(format string, a ...any) { logger.Warn("tacacs", "detalhe", fmt.Sprintf(format, a...)) }

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	logger.Info("Edge iniciado", "versao", version, "tacacs", *listen, "cliente", eng.Customer().Code, "politica", eng.Version())

	// SIGHUP recarrega a política (a sincronização com a nuvem usará o mesmo caminho).
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sig {
			if s != syscall.SIGHUP {
				logger.Info("encerrando")
				_ = l.Close()
				return
			}
			ne, err := load()
			if err != nil {
				logger.Error("política nova rejeitada; mantendo a atual", "erro", err)
				continue
			}
			if ne.Version() < srv.Policy().Version() {
				logger.Error("política nova é mais antiga que a atual; mantendo a atual", "nova", ne.Version(), "atual", srv.Policy().Version())
				continue
			}
			srv.SetPolicy(ne)
			logger.Info("política recarregada", "versao", ne.Version())
		}
	}()

	if err := srv.Serve(l); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func checkPolicy(args []string) error {
	fs := flag.NewFlagSet("check-policy", flag.ExitOnError)
	policyPath := fs.String("policy", "/etc/onegate/policy.json", "arquivo da política")
	pubkey := fs.String("pubkey", os.Getenv("ONEGATE_POLICY_PUBKEY"), "chave pública da nuvem (base64)")
	_ = fs.Parse(args)
	eng, err := loadAny(*policyPath, *pubkey)
	if err != nil {
		return err
	}
	fmt.Printf("Política válida: cliente %s, versão %d\n", eng.Customer().Code, eng.Version())
	for _, w := range eng.Warnings() {
		fmt.Println("  aviso:", w)
	}
	return nil
}

// loadAny lê a política assinada (com chave) ou o JSON puro do laboratório.
func loadAny(path, pubkey string) (*policy.Engine, error) {
	if pubkey == "" {
		return policy.Load(path)
	}
	pub, err := policy.ParsePublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	return policy.LoadSigned(path, pub)
}

// simulate avalia um acesso contra a política sem tocar em equipamento nenhum.
func simulate(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	policyPath := fs.String("policy", "/etc/onegate/policy.json", "arquivo da política")
	user := fs.String("user", "", "usuário (com ou sem domínio)")
	device := fs.String("device", "", "nome ou IP do equipamento")
	from := fs.String("from", "", "IP de origem do técnico")
	at := fs.String("at", "", "data e hora no fuso do cliente (AAAA-MM-DD HH:MM); padrão: agora")
	cmd := fs.String("cmd", "", "comando a autorizar (opcional)")
	pubkey := fs.String("pubkey", os.Getenv("ONEGATE_POLICY_PUBKEY"), "chave pública da nuvem (base64)")
	_ = fs.Parse(args)
	eng, err := loadAny(*policyPath, *pubkey)
	if err != nil {
		return err
	}
	d, ok := eng.DeviceByName(*device)
	if !ok {
		if ip, perr := netip.ParseAddr(*device); perr == nil {
			d, ok = eng.DeviceFor(ip)
		}
	}
	if !ok {
		return fmt.Errorf("equipamento %q não está na política", *device)
	}
	when := time.Now()
	if *at != "" {
		when, err = time.ParseInLocation("2006-01-02 15:04", *at, eng.Location())
		if err != nil {
			return fmt.Errorf("--at: use AAAA-MM-DD HH:MM")
		}
	}
	req := policy.Request{User: *user, Device: d, Source: *from, Time: when}
	res := eng.Evaluate(req)
	if *cmd != "" && res.Allowed {
		res = eng.AuthorizeCommand(req, *cmd)
	}
	for _, st := range res.Trail {
		fmt.Printf("  #%-3d %-10s %-40s %s\n", st.Num, st.Status, st.Name, st.Note)
	}
	verdict := "NEGADO"
	if res.Allowed {
		verdict = "PERMITIDO"
	}
	fmt.Printf("%s: %s\n", verdict, res.Reason)
	if res.Allowed {
		mfa := "não exigido"
		if res.MFA.Required {
			mfa = "TOTP (" + res.MFA.Reason + ")"
		}
		fmt.Printf("  priv-lvl %d · MFA %s\n", res.PrivLevel, mfa)
	}
	return nil
}

func readSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func hashPassword() error {
	pw, err := readSecret("Senha: ")
	if err != nil {
		return err
	}
	if len(pw) < 10 {
		return errors.New("use pelo menos 10 caracteres")
	}
	h, err := passhash.Hash(pw)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}

func totpSecret(args []string) error {
	fs := flag.NewFlagSet("totp-secret", flag.ExitOnError)
	user := fs.String("user", "", "usuário do técnico")
	customer := fs.String("customer", "", "código do cliente")
	_ = fs.Parse(args)
	if *user == "" {
		return errors.New("informe --user")
	}
	s, err := totp.NewSecret()
	if err != nil {
		return err
	}
	account := *user
	if *customer != "" {
		account += "@" + *customer
	}
	fmt.Println("Segredo:", s)
	fmt.Println("URI para o app autenticador (gere o QR Code a partir dela):")
	fmt.Println(totp.ProvisioningURI("ONE GATE", account, s))
	return nil
}

// testLogin é um cliente TACACS+ de laboratório: valida o Edge sem precisar de um equipamento.
func testLogin(args []string) error {
	fs := flag.NewFlagSet("test-login", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:49", "Edge HOST:PORTA")
	secret := fs.String("secret", "", "chave compartilhada do equipamento")
	user := fs.String("user", "", "usuário")
	pap := fs.Bool("pap", false, "usar PAP (senha+código no mesmo campo)")
	remAddr := fs.String("rem-addr", "127.0.0.1", "IP do técnico informado ao Edge")
	cmd := fs.String("cmd", "", "também testar a autorização deste comando")
	_ = fs.Parse(args)
	if *secret == "" || *user == "" {
		return errors.New("informe --secret e --user")
	}
	c := &tacplus.Client{Addr: *server, ConnConfig: tacplus.ConnConfig{Secret: []byte(*secret), ReadTimeout: 30 * time.Second, WriteTimeout: 10 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	start := &tacplus.AuthenStart{Action: tacplus.AuthenActionLogin, AuthenService: tacplus.AuthenServiceLogin,
		PrivLvl: 1, User: *user, Port: "test-login", RemAddr: *remAddr}
	if *pap {
		pw, err := readSecret("Senha (+ código, se exigido): ")
		if err != nil {
			return err
		}
		start.AuthenType, start.Data = tacplus.AuthenTypePAP, []byte(pw)
	} else {
		start.AuthenType = tacplus.AuthenTypeASCII
	}
	rep, sess, err := c.SendAuthenStart(ctx, start)
	if err != nil {
		return err
	}
	for sess != nil {
		var ans string
		if rep.NoEcho || rep.Status == tacplus.AuthenStatusGetPass {
			ans, err = readSecret(rep.ServerMsg)
		} else {
			fmt.Fprint(os.Stderr, rep.ServerMsg)
			ans, err = stdin.ReadString('\n')
			ans = strings.TrimSpace(ans)
		}
		if err != nil {
			sess.Close()
			return err
		}
		rep, err = sess.Continue(ctx, ans)
		if err != nil {
			return err
		}
		if rep.Status != tacplus.AuthenStatusGetData && rep.Status != tacplus.AuthenStatusGetPass && rep.Status != tacplus.AuthenStatusGetUser {
			sess.Close()
			sess = nil
		}
	}
	if rep.Status != tacplus.AuthenStatusPass {
		fmt.Println("Autenticação NEGADA", rep.ServerMsg)
		return nil
	}
	fmt.Println("Autenticação ACEITA")

	ar, err := c.SendAuthorRequest(ctx, &tacplus.AuthorRequest{AuthenMethod: tacplus.AuthenMethodTACACSPlus,
		AuthenType: start.AuthenType, AuthenService: tacplus.AuthenServiceLogin, User: *user, Port: "test-login",
		RemAddr: *remAddr, Arg: []string{"service=shell", "cmd="}})
	if err != nil {
		return err
	}
	fmt.Printf("Início de sessão: status=%d args=%v\n", ar.Status, ar.Arg)
	if *cmd != "" {
		f := strings.Fields(*cmd)
		a := []string{"service=shell", "cmd=" + f[0]}
		for _, x := range f[1:] {
			a = append(a, "cmd-arg="+x)
		}
		ar, err = c.SendAuthorRequest(ctx, &tacplus.AuthorRequest{AuthenMethod: tacplus.AuthenMethodTACACSPlus,
			AuthenType: start.AuthenType, AuthenService: tacplus.AuthenServiceLogin, User: *user, Port: "test-login",
			RemAddr: *remAddr, Arg: append(a, "cmd-arg=<cr>")})
		if err != nil {
			return err
		}
		res := "NEGADO"
		if ar.Status == tacplus.AuthorStatusPassAdd || ar.Status == tacplus.AuthorStatusPassRepl {
			res = "PERMITIDO"
		}
		fmt.Printf("Comando %q: %s\n", *cmd, res)
	}
	return nil
}
