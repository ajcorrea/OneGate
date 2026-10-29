# Edge: laboratório (prova técnica TACACS+)

Objetivo do dia 1: validar o servidor TACACS+ do Edge contra os equipamentos reais do laboratório
antes de construir o resto.

## 1. Subir o Edge

```bash
# Gere a política do laboratório a partir do exemplo
cp deploy/edge/policy.example.json /etc/onegate/policy.json

# Senha e TOTP dos técnicos
go run ./cmd/onegate-edge hash-password                       # cole o hash em password_hash
go run ./cmd/onegate-edge totp-secret --user alexandre.c --customer LAB
#   → cadastre a URI no app autenticador (Google/Microsoft Authenticator, Authy, Bitwarden)

# Troque todas as chaves "TROCAR-..." por chaves fortes (mínimo 16 caracteres)
go run ./cmd/onegate-edge check-policy --policy /etc/onegate/policy.json

# Rodando direto
sudo go run ./cmd/onegate-edge serve --policy /etc/onegate/policy.json --listen :49 --events /var/lib/onegate/events.jsonl

# Ou em container (Docker ou Podman)
docker build -f deploy/edge/Dockerfile -t onegate-edge .
docker run -d --name onegate-edge -p 49:4949 \
  -v /etc/onegate:/etc/onegate:ro -v /var/lib/onegate:/var/lib/onegate onegate-edge
```

A política de exemplo vem com a senha `trocar-esta-senha` e um segredo TOTP público. **Use só no laboratório.**

Depois de editar a política, recarregue sem derrubar o serviço: `kill -HUP <pid>` (ou `docker kill -s HUP onegate-edge`).

## 2. Testar sem equipamento

```bash
go run ./cmd/onegate-edge test-login --server 127.0.0.1:49 --secret <CHAVE-teste-local> \
  --user suporte.n1 --rem-addr 10.20.1.5 --cmd "display interface brief"
```

## 3. Configurar os equipamentos

Troque `192.168.88.250` pelo IP do Edge e `<CHAVE>` pela chave do equipamento na política.
**Mantenha sempre o método `local` como último recurso** (conta de emergência).

### Huawei (VRP / NE8000): modelo a validar no laboratório

```
hwtacacs-server template onegate
 hwtacacs-server authentication 192.168.88.250 49
 hwtacacs-server authorization 192.168.88.250 49
 hwtacacs-server accounting 192.168.88.250 49
 hwtacacs-server shared-key cipher <CHAVE>
#
aaa
 authentication-scheme onegate
  authentication-mode hwtacacs local
 authorization-scheme onegate
  authorization-mode hwtacacs local
  authorization-cmd 3 hwtacacs local
 accounting-scheme onegate
  accounting-mode hwtacacs
 recording-scheme onegate
  recording-mode hwtacacs onegate
 cmd recording-scheme onegate
 domain default_admin
  authentication-scheme onegate
  authorization-scheme onegate
  accounting-scheme onegate
  hwtacacs-server onegate
```

### Cisco IOS / IOS-XE

```
aaa new-model
tacacs server ONEGATE-1
 address ipv4 192.168.88.250
 key <CHAVE>
aaa group server tacacs+ ONEGATE
 server name ONEGATE-1
aaa authentication login default group ONEGATE local
aaa authorization exec default group ONEGATE local if-authenticated
aaa authorization commands 1 default group ONEGATE local if-authenticated
aaa authorization commands 15 default group ONEGATE local if-authenticated
aaa accounting exec default start-stop group ONEGATE
aaa accounting commands 1 default start-stop group ONEGATE
aaa accounting commands 15 default start-stop group ONEGATE
```

## 4. Checklist da prova técnica

Para cada fabricante, registre o resultado em `docs/lab/<fabricante>.md`:

- [ ] Login com senha + segundo prompt de código (TOTP)
- [ ] Login com senha+código no mesmo campo (`code_entry: append`)
- [ ] Janela de confiança: segundo login sem código
- [ ] `priv-lvl` aplicado na sessão
- [ ] Comando permitido e comando negado (Suporte N1)
- [ ] Accounting de cada comando em `events.jsonl`
- [ ] Senha mascarada no accounting (`local-user ... password ...`)
- [ ] Edge parado → equipamento cai para a conta local
- [ ] Atributos/formatos específicos do fabricante observados (anotar)
