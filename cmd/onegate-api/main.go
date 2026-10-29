// Comando onegate-api: a API da plataforma ONE GATE (nuvem).
//
// Configuração por variáveis de ambiente:
//
//	ONEGATE_DATABASE_URL      postgres://usuario:senha@host:5432/onegate
//	ONEGATE_SECRET_KEY        chave mestra de 32 bytes em base64 (openssl rand -base64 32)
//	ONEGATE_LISTEN            endereço HTTP (padrão :8080)
//	ONEGATE_WEB_DIR           pasta do painel compilado (web/dist), opcional
//	ONEGATE_INSECURE_COOKIES  "1" só em desenvolvimento local sem HTTPS
//	ONEGATE_TRUST_PROXY       "1" quando atrás de proxy reverso confiável
//
// Subcomandos:
//
//	onegate-api                       inicia a API (aplica as migrações)
//	onegate-api migrate               só aplica as migrações
//	onegate-api bootstrap-admin --login alexandre --name "Nome" [--email contato@exemplo.com]
//	onegate-api policy-pubkey         mostra a chave pública que os Edges usam para verificar a política
//	onegate-api export-policy --customer NSF --out politica.json   gera o pacote assinado do cliente
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/ajcorrea/onegate/internal/platform"
	"github.com/ajcorrea/onegate/internal/policy"
	"github.com/ajcorrea/onegate/internal/secretbox"
)

var version = "dev"

func main() {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "migrate":
		err = migrate()
	case "bootstrap-admin":
		err = bootstrapAdmin(args)
	case "policy-pubkey":
		err = policyPubkey()
	case "export-policy":
		err = exportPolicy(args)
	case "version":
		fmt.Println("onegate-api", version)
	default:
		fmt.Fprintln(os.Stderr, "uso: onegate-api [serve | migrate | bootstrap-admin --login L --name N [--email E] | policy-pubkey | export-policy --customer COD --out ARQ | version]")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func open(ctx context.Context) (*platform.DB, *secretbox.Box, error) {
	url := os.Getenv("ONEGATE_DATABASE_URL")
	if url == "" {
		return nil, nil, errors.New("defina ONEGATE_DATABASE_URL")
	}
	box, err := secretbox.New(os.Getenv("ONEGATE_SECRET_KEY"))
	if err != nil {
		return nil, nil, fmt.Errorf("ONEGATE_SECRET_KEY: %w", err)
	}
	db, err := platform.Open(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		return nil, nil, err
	}
	if err := db.EnsureBuiltins(ctx); err != nil {
		db.Close()
		return nil, nil, err
	}
	return db, box, nil
}

func serve() error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, box, err := open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	s := platform.NewServer(db, box, log)
	s.SecureCookies = os.Getenv("ONEGATE_INSECURE_COOKIES") != "1"
	s.TrustProxy = os.Getenv("ONEGATE_TRUST_PROXY") == "1"
	if dir := os.Getenv("ONEGATE_WEB_DIR"); dir != "" {
		s.Static = spa(dir)
	}

	addr := env("ONEGATE_LISTEN", ":8080")
	srv := &http.Server{
		Addr: addr, Handler: s.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("API ONE GATE iniciada", "versao", version, "endereco", addr, "cookies_seguros", s.SecureCookies)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// spa serve o painel compilado; rotas desconhecidas devolvem index.html (roteamento no navegador).
func spa(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join(dir, filepath.Clean("/"+r.URL.Path))
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		fs.ServeHTTP(w, r)
	})
}

func migrate() error {
	ctx := context.Background()
	db, _, err := open(ctx)
	if err != nil {
		return err
	}
	db.Close()
	fmt.Println("Migrações aplicadas.")
	return nil
}

func bootstrapAdmin(args []string) error {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ExitOnError)
	login := fs.String("login", "", "usuário (antes do @"+platform.GlobalDomain+")")
	name := fs.String("name", "", "nome completo")
	email := fs.String("email", "", "e-mail de contato (opcional)")
	_ = fs.Parse(args)
	if *login == "" || *name == "" {
		return errors.New("informe --login e --name")
	}
	ctx := context.Background()
	db, box, err := open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	pw, err := readPassword("Senha (mín. 12 caracteres): ")
	if err != nil {
		return err
	}
	s := platform.NewServer(db, box, slog.Default())
	if _, err := s.CreatePanelUser(ctx, platform.System, platform.NewPanelUser{Login: *login, Email: *email, Name: *name, Password: pw, TypeKey: "global_admin"}); err != nil {
		return err
	}
	fmt.Printf("Admin global %s@%s criado. No primeiro login o painel mostra o QR Code para cadastrar o app autenticador.\n", strings.ToLower(*login), platform.GlobalDomain)
	return nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func policyPubkey() error {
	priv, err := platform.PolicySigningKey(os.Getenv("ONEGATE_SECRET_KEY"))
	if err != nil {
		return fmt.Errorf("ONEGATE_SECRET_KEY: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	fmt.Fprintln(os.Stderr, "key_id", policy.KeyID(pub), "— use em: onegate-edge serve --pubkey <chave>")
	return nil
}

// exportPolicy gera o pacote assinado de um cliente (regras publicadas + técnicos e equipamentos
// atuais). Contém segredos: grave com permissão restrita e leve ao Edge por canal seguro.
func exportPolicy(args []string) error {
	fs := flag.NewFlagSet("export-policy", flag.ExitOnError)
	customer := fs.String("customer", "", "código do cliente (ex.: NSF)")
	out := fs.String("out", "", "arquivo de saída")
	_ = fs.Parse(args)
	if *customer == "" || *out == "" {
		return errors.New("informe --customer e --out")
	}
	ctx := context.Background()
	db, box, err := open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	priv, err := platform.PolicySigningKey(os.Getenv("ONEGATE_SECRET_KEY"))
	if err != nil {
		return err
	}
	srv := platform.NewServer(db, box, slog.Default())
	data, warnings, err := srv.ExportPolicy(ctx, *customer, func(p *policy.Policy) ([]byte, error) { return policy.Sign(p, priv) })
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("Política de %s gravada em %s (assinada, key_id %s)\n", *customer, *out, policy.KeyID(priv.Public().(ed25519.PublicKey)))
	for _, w := range warnings {
		fmt.Println("  aviso:", w)
	}
	return nil
}
