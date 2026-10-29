# ONE GATE

Plataforma da **ON TELECOM** para administrar os ativos dos clientes: autenticação de técnicos
(TACACS+/RADIUS com TOTP) através de Edges locais, e um agente Linux para saúde, atualizações,
comandos em massa e logs.

O planejamento completo, com decisões, arquitetura e cronograma, está em [`docs/planejamento.md`](docs/planejamento.md).

## Componentes

| Binário | Função |
|---|---|
| `onegate-api` | API da plataforma (nuvem) |
| `onegate-edge` | Edge instalado na rede do cliente: TACACS+ (e RADIUS) com política local |
| `onegate-agent` | Agente dos servidores Linux (em construção) |

O painel web fica em [`web/`](web).

## Desenvolvimento

Requisitos: Go 1.24+, Node 22+, Docker (ou PostgreSQL 16 local).

```bash
# Banco de desenvolvimento
docker compose -f deploy/docker-compose.dev.yml up -d

# API (aplica as migrações ao iniciar)
export ONEGATE_DATABASE_URL="postgres://onegate:onegate@localhost:5432/onegate?sslmode=disable"
go run ./cmd/onegate-api

# Cria o primeiro administrador (mostra o segredo TOTP para cadastrar no app autenticador)
go run ./cmd/onegate-api bootstrap-admin --email voce@exemplo.com --name "Seu Nome"

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

### Testes

```bash
go test ./...
```

---

Desenvolvido por Alexandre Jeronimo Correa ([github.com/ajcorrea](https://github.com/ajcorrea)) · ON TELECOM · [ontelecom.io](https://ontelecom.io)
