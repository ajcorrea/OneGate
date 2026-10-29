# Convenções do projeto ONE GATE

- Documentação, textos de interface, mensagens de erro para o usuário e commits: **português do Brasil**.
- Código (identificadores, nomes de pacotes, tabelas, colunas): **inglês**. "Cliente" no domínio = `customer` no código.
- Planejamento e decisões: `docs/planejamento.md`. Uma decisão nova ou alterada entra lá.
- Todo dado de cliente carrega `customer_id`. Toda consulta de dados de cliente passa pelo isolamento (RLS ou filtro explícito no repositório).
- Segurança não se simplifica para ganhar prazo: senhas só em Argon2id, segredos nunca em log, comandos e políticas sempre assinados, auditoria de toda ação administrativa.
- Go: biblioteca padrão primeiro; dependências novas só com licença permissiva (MIT, BSD, Apache-2.0). Nada de AGPL/ELv2/SSPL.
- Testes: `go test ./...` precisa passar antes de cada commit. Protocolos (TACACS+, RADIUS, TOTP) sempre com testes automatizados.
- Web: React + Vite + TypeScript. Cores e componentes seguem o mockup ONE GATE (azul-marinho `#1E4087`, azul-claro `#3FC1F4`, tema claro e escuro).
