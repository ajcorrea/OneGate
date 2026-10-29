-- Regras AAA: objetos, equipamentos, regras em rascunho e publicações.
--
-- * Objetos (grupos de técnicos, grupos de equipamentos, redes, perfis de comandos e horários) são
--   globais (customer_id NULL) ou de um cliente. O conteúdo de cada tipo fica em "data" e é
--   validado pela API.
-- * As regras são o rascunho editável. Elas guardam referências por ID ("group:<uuid>"), então
--   renomear um objeto não quebra regra nenhuma.
-- * Publicar grava um snapshot (regras + objetos, sem segredos). O Edge recebe sempre o último
--   snapshot global + o último do cliente, com os técnicos e equipamentos atuais.

-- MFA padrão e janela de confiança já ficam em customers; os horários das regras usam o fuso do cliente.
ALTER TABLE customers ADD COLUMN timezone text NOT NULL DEFAULT 'America/Sao_Paulo';

CREATE TABLE aaa_objects (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id uuid REFERENCES customers(id) ON DELETE RESTRICT,
  kind        text NOT NULL CHECK (kind IN ('user_group', 'device_group', 'network', 'profile', 'schedule')),
  name        text NOT NULL CHECK (length(name) BETWEEN 2 AND 60 AND position('@' IN name) = 0 AND position(':' IN name) = 0),
  description text NOT NULL DEFAULT '',
  data        jsonb NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
-- Nome único por tipo e escopo (globais entre si, e por cliente). A API também impede que um objeto
-- do cliente repita o nome de um global, porque os dois aparecem juntos na política do cliente.
CREATE UNIQUE INDEX aaa_objects_name_idx
  ON aaa_objects (kind, coalesce(customer_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(name));

-- Técnicos (pessoas com acesso aos equipamentos) em grupos de técnicos
CREATE TABLE aaa_user_group_members (
  group_id  uuid NOT NULL REFERENCES aaa_objects(id) ON DELETE CASCADE,
  person_id uuid NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, person_id)
);
CREATE INDEX aaa_user_group_members_person_idx ON aaa_user_group_members (person_id);

CREATE TABLE aaa_devices (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id          uuid NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
  name                 text NOT NULL CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$'),
  address              cidr NOT NULL,
  vendor               text NOT NULL DEFAULT '',
  model                text NOT NULL DEFAULT '',
  mfa                  text NOT NULL DEFAULT 'inherit' CHECK (mfa IN ('inherit', 'off', 'totp')),
  code_entry           text NOT NULL DEFAULT 'prompt' CHECK (code_entry IN ('prompt', 'append')),
  trust_window_seconds integer CHECK (trust_window_seconds BETWEEN 0 AND 86400),
  secret               text NOT NULL,      -- cifrado (secretbox), contexto = "aaa-device:" || id
  active               boolean NOT NULL DEFAULT true,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX aaa_devices_name_idx ON aaa_devices (customer_id, lower(name));
CREATE INDEX aaa_devices_customer_idx ON aaa_devices (customer_id);

-- Grupos do equipamento; position = 0 é o grupo principal (define a herança de MFA)
CREATE TABLE aaa_device_group_members (
  device_id uuid NOT NULL REFERENCES aaa_devices(id) ON DELETE CASCADE,
  group_id  uuid NOT NULL REFERENCES aaa_objects(id) ON DELETE CASCADE,
  position  integer NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, group_id)
);

CREATE TABLE aaa_rules (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id uuid REFERENCES customers(id) ON DELETE RESTRICT,
  position    integer NOT NULL,
  name        text NOT NULL CHECK (length(name) BETWEEN 2 AND 80),
  action      text NOT NULL CHECK (action IN ('allow', 'deny')),
  who         text[] NOT NULL DEFAULT '{}',
  where_refs  text[] NOT NULL DEFAULT '{}',
  from_refs   text[] NOT NULL DEFAULT '{}',
  what        text NOT NULL DEFAULT '',
  when_refs   text[] NOT NULL DEFAULT '{}',
  mfa         text NOT NULL DEFAULT 'device' CHECK (mfa IN ('totp', 'device', 'none')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX aaa_rules_scope_idx ON aaa_rules (customer_id, position);

CREATE TABLE aaa_publications (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id  uuid REFERENCES customers(id) ON DELETE RESTRICT,
  version      integer NOT NULL,
  snapshot     jsonb NOT NULL,
  note         text NOT NULL DEFAULT '',
  published_by uuid REFERENCES people(id) ON DELETE SET NULL,
  published_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX aaa_publications_version_idx
  ON aaa_publications (coalesce(customer_id, '00000000-0000-0000-0000-000000000000'::uuid), version);

-- RLS. Objetos e regras globais são legíveis por quem está logado (aparecem na política de todo
-- cliente); só quem tem escopo global escreve neles. Os do cliente seguem og_can_see. A API ainda
-- confere as funções (aaa.rules.view, aaa.rules.edit …) em cada escopo.
CREATE FUNCTION og_aaa_read(cid uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT og_is_admin() OR og_is_global() OR (og_user_id() IS NOT NULL AND (cid IS NULL OR og_can_see(cid)))
$$;
CREATE FUNCTION og_aaa_write(cid uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN cid IS NULL THEN og_is_admin() OR og_is_global() ELSE og_can_see(cid) END
$$;

ALTER TABLE aaa_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE aaa_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY aaa_objects_read ON aaa_objects FOR SELECT USING (og_aaa_read(customer_id));
CREATE POLICY aaa_objects_ins  ON aaa_objects FOR INSERT WITH CHECK (og_aaa_write(customer_id));
CREATE POLICY aaa_objects_upd  ON aaa_objects FOR UPDATE USING (og_aaa_write(customer_id)) WITH CHECK (og_aaa_write(customer_id));
CREATE POLICY aaa_objects_del  ON aaa_objects FOR DELETE USING (og_aaa_write(customer_id));

ALTER TABLE aaa_user_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE aaa_user_group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY aaa_ugm_read ON aaa_user_group_members FOR SELECT
  USING (EXISTS (SELECT 1 FROM aaa_objects o WHERE o.id = group_id));
CREATE POLICY aaa_ugm_write ON aaa_user_group_members FOR ALL
  USING (EXISTS (SELECT 1 FROM aaa_objects o WHERE o.id = group_id AND og_aaa_write(o.customer_id)))
  WITH CHECK (EXISTS (SELECT 1 FROM aaa_objects o WHERE o.id = group_id AND og_aaa_write(o.customer_id)));

ALTER TABLE aaa_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE aaa_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY aaa_devices_all ON aaa_devices
  USING (og_can_see(customer_id)) WITH CHECK (og_can_see(customer_id));

ALTER TABLE aaa_device_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE aaa_device_group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY aaa_dgm_all ON aaa_device_group_members
  USING (EXISTS (SELECT 1 FROM aaa_devices d WHERE d.id = device_id))
  WITH CHECK (EXISTS (SELECT 1 FROM aaa_devices d WHERE d.id = device_id));

ALTER TABLE aaa_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE aaa_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY aaa_rules_read ON aaa_rules FOR SELECT USING (og_aaa_read(customer_id));
CREATE POLICY aaa_rules_ins  ON aaa_rules FOR INSERT WITH CHECK (og_aaa_write(customer_id));
CREATE POLICY aaa_rules_upd  ON aaa_rules FOR UPDATE USING (og_aaa_write(customer_id)) WITH CHECK (og_aaa_write(customer_id));
CREATE POLICY aaa_rules_del  ON aaa_rules FOR DELETE USING (og_aaa_write(customer_id));

ALTER TABLE aaa_publications ENABLE ROW LEVEL SECURITY;
ALTER TABLE aaa_publications FORCE ROW LEVEL SECURITY;
CREATE POLICY aaa_pub_read ON aaa_publications FOR SELECT USING (og_aaa_read(customer_id));
CREATE POLICY aaa_pub_ins  ON aaa_publications FOR INSERT WITH CHECK (og_aaa_write(customer_id));
-- Publicações não se alteram nem se apagam.
