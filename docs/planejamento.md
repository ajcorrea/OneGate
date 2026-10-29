# ONE GATE: planejamento da Fase 1

Documento de referência da equipe. Registra as decisões tomadas no planejamento e o cronograma do MVP.

## 1. O que é

O ONE GATE é um ambiente online onde a equipe da ON TELECOM administra ativos dos **clientes**
(provedores de internet e empresas de outros segmentos). A Fase 1 entrega duas frentes:

1. **AAA para técnicos**: os técnicos fazem login nos equipamentos de rede e nos servidores Linux dos
   clientes via **TACACS+** (preferencial) ou **RADIUS** (quando o equipamento só suporta RADIUS).
   As funções seguem o modelo do TaraNAC. A implementação é própria, porque o TaraNAC usa a Elastic
   License 2.0, que proíbe oferecê-lo como serviço gerenciado.
2. **Agente Linux**: saúde (CPU, memória, disco, rede), atualizações pendentes (apt/dnf/yum),
   comandos em massa e logs.

Fora do escopo: autenticação de assinantes (PPPoE/hotspot). Isso continua no RADIUS do próprio cliente.

## 2. Decisões

| Tema | Decisão |
|---|---|
| Clientes | Qualquer segmento. Cada cliente tem **código de 3 letras e cor** (badge visual). Todo registro carrega `customer_id`, com isolamento no banco (row-level security). |
| Onde autentica | No **Edge**, dentro da rede do cliente. A nuvem só administra. Sem conexão com a nuvem, os logins continuam funcionando. |
| Edge | **Desde o início.** Um par de Edges por cliente (primário/secundário), em **Docker/Podman**, cada serviço em seu container. |
| Fonte da verdade | A nuvem. Nada se edita no Edge. A política vai em **pacotes numerados, assinados e cifrados**. |
| Senhas no Edge | Hash **Argon2id**. Suportados: TACACS+ (PAP/ASCII) e RADIUS PAP. Sem CHAP. PEAP/MSCHAPv2 fica para depois. |
| MFA | Somente **TOTP** (qualquer app autenticador). Funciona com o Edge online ou offline. |
| Herança de MFA | Cliente → grupo de equipamentos → equipamento (*herdar / desligado / TOTP obrigatório*). Regras de grupos de técnicos só endurecem. **O mais restritivo vence.** |
| Entrada do código | Por equipamento: **segundo prompt** ("Código MFA:") ou **senha + código juntos** (Winbox e similares). |
| Janela de confiança | Depois de um código válido, o mesmo técnico, a partir do mesmo IP, não digita outro código naquele cliente durante a janela (padrão 1 h no núcleo). |
| TOTP: cuidados | Código de uso único (sincronizado entre os 2 Edges), tolerância de ±1 passo de 30 s, NTP obrigatório, códigos de recuperação. |
| Offline | Prazo máximo offline por cliente. Contas de emergência locais em cada equipamento (`authentication-mode hwtacacs local`), com alerta quando usadas. |
| Desligar MFA | Exige aprovação de outro administrador e fica na auditoria. |
| Auditoria Fase 1 | **Comandos digitados, em texto.** Equipamentos via accounting TACACS+. Linux via PAM (`pam_tacplus`) e captura de comandos pelo **auditd** (o agente configura), com mascaramento de senhas. Sem gravação de saída/sessão. |
| Agente | **Pacote .deb/.rpm** em repositório próprio assinado (atualiza via apt/dnf), serviço systemd, binário Go. Não roda em container. |
| Transporte | **WireGuard em espaço de usuário** (sem interface no host), com plano B TLS/443. Dentro do túnel: **mTLS** e **tarefas assinadas**. Os pares nunca se enxergam. |
| Cadastro | Token de uso único gerado no painel, trocado por certificado próprio do agente/Edge. |
| LDAP/AD | Fora da Fase 1. |

## 3. Arquitetura

```
                 ┌──────────────────────── Nuvem ONE GATE ────────────────────────┐
  Equipe ──HTTPS─▶  Painel web ── API ── PostgreSQL (cadastros, políticas, auditoria)│
                 │                  │      Métricas (séries temporais)              │
                 │                  │      Logs/accounting (ClickHouse, depois)     │
                 │           Gateways (WireGuard + NATS)                            │
                 └──────────────────────────▲──────────────▲───────────────────────┘
                                            │ saída         │ saída
                          ┌─────────────────┴──┐     ┌──────┴────────────┐
   Rede do cliente        │ Edge primário      │     │ Agente (.deb/.rpm)│
                          │ TACACS+ · RADIUS   │     │ em cada servidor  │
   Equipamentos ─TACACS+─▶│ política local     │     └───────────────────┘
   Servidores (PAM) ─────▶│ fila de accounting │
                          └────────────────────┘ + Edge secundário
```

## 4. Componentes do repositório

| Caminho | Conteúdo |
|---|---|
| `cmd/onegate-api` | API da plataforma (nuvem) |
| `cmd/onegate-edge` | Edge: TACACS+ (e RADIUS via FreeRADIUS, a partir do dia 8) |
| `cmd/onegate-agent` | Agente Linux (a partir do dia 3) |
| `internal/policy` | Motor de política: usuários, grupos, regras, autorização de comandos, MFA |
| `internal/totp` | TOTP (RFC 6238) com proteção contra reuso |
| `internal/tacacs` | Servidor TACACS+ ligado ao motor de política |
| `internal/platform` | API da plataforma: clientes, equipe, sessões, auditoria |
| `internal/platform/migrations` | Migrações SQL do PostgreSQL (embutidas no binário) |
| `internal/secretbox` | Cifragem AES-256-GCM de segredos guardados no banco (sementes TOTP) |
| `internal/edgelog` | Eventos de AAA do Edge (JSONL, fila local para a nuvem) |
| `web` | Painel (React + Vite + TypeScript) |
| `deploy` | Docker Compose para desenvolvimento |

## 5. Cronograma do MVP (15 dias)

Situação: dias 1 e 2 concluídos (ver seção 8).

| Dia | Entrega |
|---|---|
| 1 | Laboratório e stack. Prova técnica: TACACS+ respondendo a Huawei e MikroTik |
| 2 | Plataforma base: login com TOTP, clientes (badge), equipe e papéis, isolamento por cliente |
| 3 | Canal seguro: cadastro por token → certificado, WireGuard + mTLS, plano B TLS/443 |
| 4 | Agente: métricas e verificação de pacotes; .deb/.rpm e repositório assinado |
| 5 | Telas Visão geral, Servidores e Detalhe do servidor |
| 6 | Edge: TACACS+ completo em container |
| 7 | Equipamentos, grupos e políticas no painel; pacote assinado; sincronização; banco local cifrado; fila offline |
| 8 | FreeRADIUS em container usando a mesma política |
| 9 | TOTP no Edge completo: herança, janela, uso único entre os 2 Edges, prazo offline |
| 10 | Painel AAA, log de comandos, cadastro de equipamento com gerador de configuração por fabricante |
| 11 | Comandos em massa: tarefas assinadas, `@update`, saída ao vivo |
| 12 | Linux: PAM (TACACS+) e captura de comandos via auditd com mascaramento |
| 13 | Instalador do Edge em um comando, testador de política, alertas básicos |
| 14 | Piloto interno na ON TELECOM (Edge duplo, equipamentos e servidores reais, teste offline) |
| 15 | Correções do piloto e documentação de instalação |

**Antes do primeiro cliente externo (+5 a 7 dias):** revisão de segurança/pentest, backup e
recuperação, aprovação dupla de comandos, logs sob demanda, imagem pronta do Edge (VM) e
atualização escalonada.

## 6. Fase 2

NCM (backup, diff, desvio, verificação da conta de emergência), bloqueio de comandos no Linux,
gravação de sessão/bastion, 802.1X/NAC, descoberta, PKI, relatórios, HA da nuvem, app com push, LDAP.

## 7. Escalabilidade

- A autenticação nunca passa pela nuvem, então o AAA escala com o número de Edges.
- API sem estado; gateways escalam adicionando nós; métricas com redução automática
  (15 s → 1 min → 1 h); logs particionados por cliente e mês.
- Estágios: até ~50 clientes em 1–2 servidores com Docker Compose; centenas com banco e logs
  separados; cliente grande pode ter instância dedicada.
- A nuvem aceita agentes/Edges da versão atual e da anterior.
- Atualização dos Edges escalonada (ON TELECOM → alguns clientes → todos). Os 2 Edges de um cliente
  nunca atualizam ao mesmo tempo.

## 8. Andamento

### Dias 1 e 2 (concluídos)

- **Edge, TACACS+:** login ASCII/PAP, TOTP por segundo prompt ou senha+código, janela de confiança,
  anti-reuso de código, bloqueio por excesso de falhas, autorização de sessão e de comando,
  accounting com senhas mascaradas, chave própria por equipamento, recarga da política sem
  reiniciar (SIGHUP). Ferramenta `test-login` para o laboratório.
  **Pendente:** validar com Huawei/Cisco/Datacom reais (`deploy/edge/README.md`).
- **Plataforma:** clientes com badge, equipe, papéis por cliente, login com senha + TOTP obrigatório
  (cadastro por QR Code no primeiro acesso, códigos de recuperação), sessões, auditoria somente
  acréscimo, isolamento por cliente no banco (RLS com FORCE).
- **Painel:** login/cadastro do TOTP, visão geral, clientes, equipe e permissões, auditoria,
  temas claro e escuro.

Decisão tomada na implementação: o painel e os equipamentos usam **o mesmo usuário e o mesmo TOTP**
de cada técnico (um cadastro só). A sincronização da senha e do TOTP para os Edges entra no dia 7.
