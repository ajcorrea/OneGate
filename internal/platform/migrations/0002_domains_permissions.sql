-- Domínios e permissões do painel em árvore.
--
-- * Cada cliente tem um domínio (ex.: netsulfibra.com.br). O domínio global (onegate.systems) é da
--   equipe ON TELECOM. Uma pessoa pertence ao domínio global (people.customer_id NULL) ou ao de um
--   cliente, e só existe nesse cliente.
-- * Logins no formato usuario@dominio no painel e nos equipamentos (credenciais diferentes).
-- * Permissões do painel: tipos de acesso (escopo global ou por cliente) → grupos (tipo base +
--   exceções) → usuário (exceções). O catálogo de funções e os tipos prontos ficam no código (Go).

-- Clientes ganham domínio
ALTER TABLE customers ADD COLUMN domain text;
UPDATE customers SET domain = lower(code) || '.cliente.invalid' WHERE domain IS NULL;
ALTER TABLE customers ALTER COLUMN domain SET NOT NULL;
ALTER TABLE customers ADD CONSTRAINT customers_domain_fmt
  CHECK (domain ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$');
CREATE UNIQUE INDEX customers_domain_idx ON customers (domain);

-- Pessoa pertence a um domínio
ALTER TABLE people ADD COLUMN customer_id uuid REFERENCES customers(id) ON DELETE RESTRICT;
CREATE INDEX people_customer_idx ON people (customer_id);

-- Login do painel: usuario@dominio (o e-mail de contato fica em people.email)
DROP INDEX panel_accounts_login_idx;
ALTER TABLE panel_accounts RENAME COLUMN login_email TO login;
CREATE UNIQUE INDEX panel_accounts_login_idx ON panel_accounts (lower(login));

-- Login nos equipamentos: usuario@dominio
ALTER TABLE device_accounts DROP CONSTRAINT device_accounts_username_check;
UPDATE device_accounts SET username = username || '@onegate.systems' WHERE position('@' IN username) = 0;
ALTER TABLE device_accounts ADD CONSTRAINT device_accounts_username_fmt
  CHECK (username ~ '^[a-z0-9][a-z0-9._-]{1,31}@[a-z0-9.-]+$');

-- Quem acessa o quê nos equipamentos passa a ser decidido pelas regras AAA (por cliente/global).
DROP TABLE device_access;

-- Tipos de acesso (os quatro prontos são criados pela API ao iniciar)
CREATE TABLE access_types (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key         text UNIQUE,                 -- global_admin, global_operator, customer_admin, customer_operator
  name        text NOT NULL CHECK (length(name) BETWEEN 2 AND 60),
  description text NOT NULL DEFAULT '',
  scope       text NOT NULL CHECK (scope IN ('global', 'customer')),
  builtin     boolean NOT NULL DEFAULT false,
  full_access boolean NOT NULL DEFAULT false, -- Admin global: tudo, sem restrição
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CHECK (NOT full_access OR scope = 'global')
);
CREATE UNIQUE INDEX access_types_name_idx ON access_types (lower(name));

CREATE TABLE access_type_grants (
  type_id  uuid NOT NULL REFERENCES access_types(id) ON DELETE CASCADE,
  function text NOT NULL,
  PRIMARY KEY (type_id, function)
);

-- Grupos do painel: globais (customer_id NULL) ou de um cliente
CREATE TABLE panel_groups (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL CHECK (length(name) BETWEEN 2 AND 60),
  customer_id  uuid REFERENCES customers(id) ON DELETE CASCADE,
  base_type_id uuid NOT NULL REFERENCES access_types(id) ON DELETE RESTRICT,
  description  text NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX panel_groups_name_idx ON panel_groups (lower(name), coalesce(customer_id, '00000000-0000-0000-0000-000000000000'));

CREATE TABLE panel_group_members (
  group_id  uuid NOT NULL REFERENCES panel_groups(id) ON DELETE CASCADE,
  person_id uuid NOT NULL REFERENCES panel_accounts(person_id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, person_id)
);

CREATE TABLE panel_group_overrides (
  group_id uuid NOT NULL REFERENCES panel_groups(id) ON DELETE CASCADE,
  function text NOT NULL,
  effect   text NOT NULL CHECK (effect IN ('allow', 'deny')),
  PRIMARY KEY (group_id, function)
);

-- Usuário: tipo direto (opcional), exceções e clientes atribuídos (tipos de escopo por cliente)
ALTER TABLE panel_accounts ADD COLUMN access_type_id uuid REFERENCES access_types(id) ON DELETE RESTRICT;

CREATE TABLE panel_user_overrides (
  person_id uuid NOT NULL REFERENCES panel_accounts(person_id) ON DELETE CASCADE,
  function  text NOT NULL,
  effect    text NOT NULL CHECK (effect IN ('allow', 'deny')),
  PRIMARY KEY (person_id, function)
);

CREATE TABLE panel_user_customers (
  person_id   uuid NOT NULL REFERENCES panel_accounts(person_id) ON DELETE CASCADE,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  PRIMARY KEY (person_id, customer_id)
);

-- Administradores existentes viram Admin global quando os tipos prontos forem criados pela API.
ALTER TABLE panel_accounts ADD COLUMN legacy_admin boolean NOT NULL DEFAULT false;
UPDATE panel_accounts SET legacy_admin = is_admin;

-- RLS: o escopo agora vem do domínio, dos tipos globais e dos clientes atribuídos.
DROP POLICY audit_read ON audit_log;
DROP FUNCTION og_can(uuid, text, text);
DROP TABLE panel_permissions;
ALTER TABLE panel_accounts DROP COLUMN is_admin;

-- onegate.global = a pessoa tem algum tipo de escopo global (vê todos os clientes no painel).
CREATE FUNCTION og_is_global() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT coalesce(current_setting('onegate.global', true), '') = 'true'
$$;

CREATE OR REPLACE FUNCTION og_can_see(cid uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT og_is_admin() OR og_is_global()
    OR EXISTS (SELECT 1 FROM panel_user_customers u WHERE u.customer_id = cid AND u.person_id = og_user_id())
    OR EXISTS (SELECT 1 FROM people p WHERE p.id = og_user_id() AND p.customer_id = cid)
$$;

-- Eventos da plataforma (sem cliente) ficam visíveis a quem tem escopo global; a API ainda filtra
-- pela função "Auditoria: ver" em cada escopo.
CREATE POLICY audit_read ON audit_log FOR SELECT
  USING (og_is_admin() OR og_is_global() OR (customer_id IS NOT NULL AND og_can_see(customer_id)));
