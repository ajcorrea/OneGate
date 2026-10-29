# Roteiro de testes do laboratório

Todos os testes saem da **VM do ONE GATE**. Ela tem dois IPs de origem:
- `10.99.0.10`: a "rede NOC", de onde entram `noc.lab` e `backup`;
- `10.99.0.50`: o "notebook do técnico", de onde entra `suporte.n1`.

O `ssh -b` escolhe a origem. Senhas e TOTPs estão em `credenciais-lab.txt`.

Deixe um terminal aberto com `sudo tail -f dados/edge/events.jsonl` para ver cada decisão do Edge.
Para conferir o porquê de cada resultado, use o **Simulador** na tela Regras de acesso do painel.

## Regras publicadas pelo instalador

| # | Escopo | Regra | Quem | Onde | De onde | O que | Quando | MFA |
|---|---|---|---|---|---|---|---|---|
| 1 | Global | NOC: acesso total | Grupo NOC | Todos | 10.99.0.10 | Acesso total (priv 15) | Sempre | TOTP |
| 2 | LAB | Backup de configuração | Contas de serviço | Todos | 10.99.0.10 | Backup (show run) | Sempre | Sem MFA |
| 3 | LAB | Terceirizados fora do núcleo | Terceirizados | Núcleo | Qualquer IP | **Negar** | | |
| 4 | LAB | Suporte N1: somente leitura | Suporte N1 | Todos | 10.99.0.50 | Somente leitura (priv 5) | Sempre | Segue o equipamento |
| 5 | LAB | Terceirizados: horário comercial | Terceirizados | Acesso, Borda | Qualquer IP | Sem roteamento | Seg–sex 8h–18h | TOTP |

MFA dos grupos: Núcleo = TOTP; Acesso = desligado; Borda = herda do cliente (TOTP).

## Arista vEOS (10.99.0.2, grupo Acesso)

| # | Teste | Comando | Esperado |
|---|---|---|---|
| A1 | Suporte entra sem MFA (Acesso desligado) | `ssh -b 10.99.0.50 suporte.n1@10.99.0.2` | Entra com priv 5 (prompt `>`) |
| A2 | Leitura permitida | `show version` · `show interfaces status` | Funciona |
| A3 | Proibido no perfil | `show running-config` · `configure` | "Command authorization failed" |
| A4 | Origem errada | `ssh -b 10.99.0.10 suporte.n1@10.99.0.2` | Recusado (nenhuma regra) |
| A5 | Usuário com domínio | `ssh -b 10.99.0.50 suporte.n1@lab.ontelecom.io@10.99.0.2` | Igual ao A1 |
| A6 | Terceirizado com TOTP | `ssh terceiro@10.99.0.2` (seg–sex, 8h–18h) | Pede o código (ou senha+6 dígitos no mesmo campo); priv 15 |
| A7 | Terceirizado sem BGP | `configure` → `router bgp 65000` | Negado; `interface Ethernet1` funciona |
| A8 | Fora do horário | Repetir A6 à noite ou no fim de semana | Recusado |
| A9 | NOC | `ssh -b 10.99.0.10 noc.lab@10.99.0.2` | TOTP pedido, priv 15, tudo liberado |
| A10 | Janela de confiança | Repetir A9 em seguida | Só a senha (janela do cliente: 1 h) |
| A11 | Senha errada 5 vezes | 5 × `ssh suporte.n1@...` com senha errada | 6ª tentativa bloqueada por 10 min, mesmo com a senha certa |
| A12 | Backup sem MFA | `ssh -b 10.99.0.10 backup@10.99.0.2 "show running-config"` | Sai a configuração |
| A13 | Senha mascarada | Como NOC: `configure` → `username x secret Teste123` | No `events.jsonl` aparece `secret ****` |
| A14 | Edge fora do ar | `sudo docker compose stop edge` → `ssh emergencia@10.99.0.2` | Entra com a conta local; depois `start edge` |
| A15 | Mudar o perfil no painel | Objetos AAA → Perfis → Somente leitura: acrescente `show interfaces *` em Negados, salve e rode `sudo ./publicar-politica.sh` | `show interfaces status` passa a ser negado (objeto vale sem publicar regras) |

## Huawei NE40E (10.99.0.1, grupo Núcleo) — quando houver imagem

| # | Teste | Esperado |
|---|---|---|
| H1 | `ssh -b 10.99.0.50 suporte.n1@10.99.0.1` | Senha e depois "Código MFA" (Núcleo exige TOTP); `display version` ok; `display current-configuration` negado |
| H2 | `ssh terceiro@10.99.0.1` | Recusado pela regra 3 (terceirizado no núcleo) |
| H3 | Login com `suporte.n1@lab.ontelecom.io` | Anote o comportamento: o Huawei trata "@..." como domínio AAA |
| H4 | `ssh -b 10.99.0.10 noc.lab@10.99.0.1` | TOTP, nível 3, tudo liberado |

## Cisco IOSv (10.99.0.3, grupo Borda) — quando houver imagem

Mesmos testes do Arista. Borda herda TOTP do cliente, então o `suporte.n1` também recebe o pedido de código.

## O que anotar em cada equipamento

São esses detalhes que ajustam o Edge antes de ir para o cliente:
- [ ] O código TOTP veio num **segundo prompt** ou precisou ir **junto da senha**? (SSH costuma usar PAP)
- [ ] O `rem_addr` no `events.jsonl` é o IP do técnico? (sem isso, "De onde" não funciona)
- [ ] O priv-lvl foi aplicado (prompt `>` ou `#`)?
- [ ] Como cada comando chega ao Edge (campo `command` no `events.jsonl`)? Abreviações (`sh ver`) são expandidas?
- [ ] Comandos do modo de configuração passam pela autorização?
- [ ] Accounting de início e fim de sessão aparece?
- [ ] O equipamento cai para a conta local quando o Edge para? Em quanto tempo?
