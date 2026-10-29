-- ONE GATE: esquema inicial da plataforma.
--
-- Pessoas e acessos: uma pessoa pode ter dois acessos INDEPENDENTES, cada um com credenciais próprias:
--   * panel_accounts  → login no painel ONE GATE (e-mail, senha, TOTP) + permissões por cliente e módulo
--   * device_accounts → login nos equipamentos e servidores dos clientes (usuário, senha, TOTP próprios),
--                       publicado para os Edges dos clientes liberados em device_access
-- Vazar a senha do painel não dá acesso aos equipamentos, e vice-versa.
--
-- Isolamento por cliente: tabelas com customer_id usam row-level security (RLS) com FORCE.
-- A API informa quem está agindo em cada transação via set_config('onegate.user_id' / 'onegate.is_admin').

CREATE FUNCTION og_user_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('onegate.user_id', true), '')::uuid
$$;

CREATE FUNCTION og_is_admin() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT coalesce(current_setting('onegate.is_admin', true), '') = 'true'
$$;

-- Clientes (provedores e empresas de qualquer segmento)
CREATE TABLE customers (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code                 text NOT NULL UNIQUE CHECK (code ~ '^[A-Z0-9]{3}$'),
  name                 text NOT NULL CHECK (length(name) BETWEEN 2 AND 120),
  segment              text NOT NULL DEFAULT 'provedor',
  color                text NOT NULL CHECK (color ~ '^#[0-9A-Fa-f]{6}$'),
  mfa                  text NOT NULL DEFAULT 'totp' CHECK (mfa IN ('off', 'totp')),
  trust_window_seconds integer NOT NULL DEFAULT 3600 CHECK (trust_window_seconds BETWEEN 0 AND 86400),
  active               boolean NOT NULL DEFAULT true,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now()
);

-- Pessoas (equipe da ON TELECOM e terceiros)
CREATE TABLE people (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL CHECK (length(name) BETWEEN 2 AND 120),
  email       text,
  phone       text,
  active      boolean NOT NULL DEFAULT true,   -- desativar a pessoa bloqueia os dois acessos
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Acesso ao painel ONE GATE
CREATE TABLE panel_accounts (
  person_id      uuid PRIMARY KEY REFERENCES people(id) ON DELETE CASCADE,
  login_email    text NOT NULL,
  password_hash  text NOT NULL,
  totp_secret    text,               -- cifrado (secretbox), contexto = "panel:" || person_id
  totp_enabled   boolean NOT NULL DEFAULT false,
  totp_last_step bigint,             -- último passo TOTP aceito: impede reuso entre instâncias da API
  is_admin       boolean NOT NULL DEFAULT false,  -- administrador da plataforma: todos os clientes e cadastros
  active         boolean NOT NULL DEFAULT true,
  last_login_at  timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX panel_accounts_login_idx ON panel_accounts (lower(login_email));

CREATE TABLE recovery_codes (
  person_id  uuid NOT NULL REFERENCES panel_accounts(person_id) ON DELETE CASCADE,
  code_hash  text NOT NULL,
  used_at    timestamptz,
  PRIMARY KEY (person_id, code_hash)
);

-- Permissões no painel: por cliente e por módulo.
--   aaa       Acesso à rede: equipamentos, políticas, log de comandos
--   servers   Servidores: saúde, atualizações, logs
--   commands  Comandos em massa (write = executar)
--   audit     Auditoria do cliente
CREATE TABLE panel_permissions (
  person_id   uuid NOT NULL REFERENCES panel_accounts(person_id) ON DELETE CASCADE,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  module      text NOT NULL CHECK (module IN ('aaa', 'servers', 'commands', 'audit')),
  level       text NOT NULL CHECK (level IN ('read', 'write')),
  PRIMARY KEY (person_id, customer_id, module)
);

-- Acesso aos equipamentos e servidores dos clientes (credencial publicada para os Edges)
CREATE TABLE device_accounts (
  person_id           uuid PRIMARY KEY REFERENCES people(id) ON DELETE CASCADE,
  username            text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._-]{2,31}$'),
  password_hash       text NOT NULL,
  totp_secret         text,          -- cifrado (secretbox), contexto = "device:" || person_id
  active              boolean NOT NULL DEFAULT true,
  password_changed_at timestamptz NOT NULL DEFAULT now(),
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

-- Em quais clientes a credencial de equipamento vale (grupos de técnicos por cliente chegam no dia 7)
CREATE TABLE device_access (
  person_id   uuid NOT NULL REFERENCES device_accounts(person_id) ON DELETE CASCADE,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  PRIMARY KEY (person_id, customer_id)
);

-- Visibilidade de um cliente no painel: administrador ou qualquer permissão nele.
CREATE FUNCTION og_can_see(cid uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT og_is_admin() OR EXISTS (
    SELECT 1 FROM panel_permissions p WHERE p.customer_id = cid AND p.person_id = og_user_id()
  )
$$;

-- Permissão num módulo de um cliente. 'write' implica 'read'.
CREATE FUNCTION og_can(cid uuid, mod text, lvl text) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT og_is_admin() OR EXISTS (
    SELECT 1 FROM panel_permissions p
    WHERE p.customer_id = cid AND p.person_id = og_user_id() AND p.module = mod
      AND (lvl = 'read' OR p.level = 'write')
  )
$$;

-- Sessões do painel. Guardamos só o SHA-256 do token.
CREATE TABLE sessions (
  token_hash    text PRIMARY KEY,
  person_id     uuid NOT NULL REFERENCES panel_accounts(person_id) ON DELETE CASCADE,
  mfa_verified  boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  ip            text,
  user_agent    text
);
CREATE INDEX sessions_person_idx ON sessions (person_id);

-- Auditoria: só acréscimo.
CREATE TABLE audit_log (
  id           bigserial PRIMARY KEY,
  at           timestamptz NOT NULL DEFAULT now(),
  actor_id     uuid REFERENCES people(id) ON DELETE SET NULL,
  actor_label  text NOT NULL,
  customer_id  uuid REFERENCES customers(id) ON DELETE SET NULL,
  action       text NOT NULL,
  target_type  text,
  target_id    text,
  ip           text,
  details      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_customer_idx ON audit_log (customer_id, at DESC);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);

CREATE FUNCTION og_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log é somente acréscimo';
END
$$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION og_audit_append_only();

-- Row-level security
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers FORCE ROW LEVEL SECURITY;
CREATE POLICY customers_read  ON customers FOR SELECT USING (og_can_see(id));
CREATE POLICY customers_write ON customers FOR INSERT WITH CHECK (og_is_admin());
CREATE POLICY customers_upd   ON customers FOR UPDATE USING (og_is_admin()) WITH CHECK (og_is_admin());
CREATE POLICY customers_del   ON customers FOR DELETE USING (og_is_admin());

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
-- Leitura: administradores veem tudo; os demais só eventos de clientes onde têm o módulo Auditoria.
CREATE POLICY audit_read   ON audit_log FOR SELECT USING (og_is_admin() OR (customer_id IS NOT NULL AND og_can(customer_id, 'audit', 'read')));
CREATE POLICY audit_insert ON audit_log FOR INSERT WITH CHECK (true);
