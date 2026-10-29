# ONE GATE

Plataforma da **ON TELECOM** para administrar os ativos dos clientes: autenticação de técnicos
(TACACS+/RADIUS com TOTP) através de Edges locais, e um agente Linux para saúde, atualizações,
comandos em massa e logs.

O planejamento completo, com decisões, arquitetura e cronograma, está em [`docs/planejamento.md`](docs/planejamento.md).

## Componentes

| Binário | Função |
|---|---|
| `onegate-api` | API da plataforma (nuvem) e painel web |
| `onegate-edge` | Edge instalado na rede do cliente: TACACS+ (e RADIUS) com política local |
| `onegate-agent` | Agente dos servidores Linux (em construção) |

O painel web fica em [`web/`](web).

## Desenvolvimento

Requisitos: Go 1.24+, Node 22+, Docker (ou PostgreSQL 16 local).

```bash
# Banco de desenvolvimento
docker compose -f deploy/docker-compose.dev.yml up -d

# Variáveis (veja .env.example)
export ONEGATE_DATABASE_URL="postgres://onegate:onegate@localhost:5432/onegate?sslmode=disable"
export ONEGATE_SECRET_KEY="$(openssl rand -base64 32)"   # guarde: sem ela os TOTP não decifram
export ONEGATE_INSECURE_COOKIES=1                         # só em desenvolvimento sem HTTPS

# Primeiro Admin global (login seu.usuario@onegate.systems; o TOTP é cadastrado por QR Code no primeiro login)
go run ./cmd/onegate-api bootstrap-admin --login seu.usuario --name "Seu Nome" --email contato@exemplo.com

# API (aplica as migrações ao iniciar)
go run ./cmd/onegate-api

# Painel web
cd web && npm install && npm run dev
```

### Edge (prova técnica TACACS+)

```bash
go run ./cmd/onegate-edge hash-password            # gera o hash Argon2id de uma senha
go run ./cmd/onegate-edge totp-secret              # gera um segredo TOTP
go run ./cmd/onegate-edge serve --policy deploy/edge/policy.example.json --listen :49
```

Configure o equipamento para usar o IP do Edge como servidor TACACS+, com a chave definida em
`policy.example.json`. Os comandos executados ficam em `accounting.jsonl`.

Com a plataforma no ar, a política sai das regras publicadas no painel (Regras de acesso), assinada:

```bash
go run ./cmd/onegate-api policy-pubkey                                   # chave pública para os Edges
go run ./cmd/onegate-api export-policy --customer NSF --out policy.json  # contém segredos (arquivo 600)
go run ./cmd/onegate-edge serve --policy policy.json --pubkey <chave> --listen :49
go run ./cmd/onegate-edge simulate --policy policy.json --pubkey <chave> \
  --user pedro.lima --device bng-01 --from 172.16.50.8 --cmd "display version"
```

### Testes

```bash
go test ./...
# Integração com PostgreSQL (apaga e recria o esquema do banco de teste):
ONEGATE_TEST_DATABASE_URL="postgres://onegate:onegate@localhost:5432/onegate_test?sslmode=disable" go test ./internal/platform/
```

### Produção (provisório)

```bash
cd web && npm ci && npm run build && cd ..
go build -o onegate-api ./cmd/onegate-api
ONEGATE_WEB_DIR=./web/dist ./onegate-api      # API + painel na mesma porta, atrás de HTTPS
```

---

Desenvolvido por Alexandre Jeronimo Correa ([github.com/ajcorrea](https://github.com/ajcorrea)) · ON TELECOM · [ontelecom.io](https://ontelecom.io)
