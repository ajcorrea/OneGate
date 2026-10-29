-- ONE GATE: esquema inicial da plataforma.
-- Isolamento por cliente: as tabelas com customer_id usam row-level security (RLS) com FORCE,
-- então nem o dono das tabelas enxerga dados de um cliente sem permissão. A API informa quem
-- está agindo em cada transação via set_config('onegate.user_id' / 'onegate.is_admin').

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

-- Equipe da ON TELECOM. O username é o mesmo usado para logar nos equipamentos (TACACS+/RADIUS).
CREATE TABLE staff_users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email          text NOT NULL,
  username       text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._-]{2,31}$'),
  name           text NOT NULL,
  password_hash  text NOT NULL,
  totp_secret    text,               -- cifrado (secretbox), contexto = id do usuário
  totp_enabled   boolean NOT NULL DEFAULT false,
  totp_last_step bigint,             -- último passo TOTP aceito: impede reuso do código
                                     -- mesmo com várias instâncias da API
  is_admin       boolean NOT NULL DEFAULT false,
  active         boolean NOT NULL DEFAULT true,
  last_login_at  timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX staff_users_email_idx ON staff_users (lower(email));

CREATE TABLE recovery_codes (
  user_id    uuid NOT NULL REFERENCES staff_users(id) ON DELETE CASCADE,
  code_hash  text NOT NULL,
  used_at    timestamptz,
  PRIMARY KEY (user_id, code_hash)
);

-- Papel de cada técnico em cada cliente.
CREATE TABLE staff_customer_roles (
  user_id     uuid NOT NULL REFERENCES staff_users(id) ON DELETE CASCADE,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  role        text NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
  PRIMARY KEY (user_id, customer_id)
);

CREATE FUNCTION og_can_see(cid uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT og_is_admin() OR EXISTS (
    SELECT 1 FROM staff_customer_roles r WHERE r.customer_id = cid AND r.user_id = og_user_id()
  )
$$;

-- Sessões do painel. Guardamos só o SHA-256 do token.
CREATE TABLE sessions (
  token_hash    text PRIMARY KEY,
  user_id       uuid NOT NULL REFERENCES staff_users(id) ON DELETE CASCADE,
  mfa_verified  boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  ip            text,
  user_agent    text
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- Auditoria: só acréscimo.
CREATE TABLE audit_log (
  id           bigserial PRIMARY KEY,
  at           timestamptz NOT NULL DEFAULT now(),
  actor_id     uuid REFERENCES staff_users(id) ON DELETE SET NULL,
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
-- Leitura: administradores veem tudo; os demais só eventos dos clientes onde têm papel.
CREATE POLICY audit_read   ON audit_log FOR SELECT USING (og_is_admin() OR (customer_id IS NOT NULL AND og_can_see(customer_id)));
-- Escrita: a API grava em nome de quem está agindo (ou de um processo do sistema).
CREATE POLICY audit_insert ON audit_log FOR INSERT WITH CHECK (true);
