import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import QRCode from "qrcode";
import { api, ApiError, formatDate, GLOBAL_DOMAIN, type AccessType, type CatalogMenu, type Customer, type PanelGroup, type Person } from "../api";
import { useAuth } from "../auth";
import { CustomerBadge } from "../components/CustomerBadge";
import { Icon } from "../components/Icon";
import { PermissionTree } from "../components/PermissionTree";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : "Erro inesperado.";
}

type Ctx = { customers: Customer[]; types: AccessType[]; groups: PanelGroup[]; catalog: CatalogMenu[] };

export function DomainTag({ person, customers }: { person: { customer_id: string | null; domain: string }; customers: Customer[] }) {
  const c = customers.find((x) => x.id === person.customer_id);
  if (c) return <CustomerBadge code={c.code} name={"@" + c.domain} color={c.color} />;
  return <span className="pill pill-info">@{person.domain || GLOBAL_DOMAIN}</span>;
}

export function People() {
  const { can } = useAuth();
  const [list, setList] = useState<Person[]>([]);
  const [ctx, setCtx] = useState<Ctx>({ customers: [], types: [], groups: [], catalog: [] });
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  const load = async () => {
    try {
      const [p, customers, types, groups, catalog] = await Promise.all([
        api.get<Person[]>("/api/people"), api.get<Customer[]>("/api/customers"), api.get<AccessType[]>("/api/access-types"),
        api.get<PanelGroup[]>("/api/panel-groups"), api.get<CatalogMenu[]>("/api/permissions/catalog"),
      ]);
      setList(p);
      setCtx({ customers, types, groups, catalog });
    } catch (e) {
      setError(errMsg(e));
    }
  };
  useEffect(() => {
    void load();
  }, []);

  const typeName = (id: string | null) => ctx.types.find((t) => t.id === id)?.name;
  const canCreate = can("admin.people.edit") || ctx.customers.some((c) => can("admin.people.edit", c.id));
  const editing = list.find((p) => p.id === editingId) ?? null;
  const replace = (p: Person) => setList((l) => l.map((x) => (x.id === p.id ? p : x)));
  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (q.length < 2) return list;
    return list.filter((p) => [p.name, p.domain, p.panel?.login, p.device?.username, p.email].some((v) => v?.toLowerCase().includes(q)));
  }, [list, filter]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Pessoas e acessos</h1>
          <p>Cada pessoa pertence a um domínio: <strong>@{GLOBAL_DOMAIN}</strong> (equipe global) ou o domínio de um cliente. O acesso ao painel e o acesso aos equipamentos têm credenciais separadas.</p>
        </div>
        {canCreate && <button className="btn btn-primary" onClick={() => setCreating(true)}><Icon name="plus" /> Nova pessoa</button>}
      </div>
      {error && <div className="alert alert-err">{error}</div>}

      <label className="field" style={{ maxWidth: 420 }}>
        <span className="sr-only">Buscar pessoa</span>
        <input className="input" type="search" placeholder="Buscar por nome, login ou domínio…" value={filter} onChange={(e) => setFilter(e.target.value)} />
      </label>

      <section className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Pessoa</th><th>Domínio</th><th>Painel ONE GATE</th><th>Equipamentos (AAA)</th><th>Situação</th></tr>
            </thead>
            <tbody>
              {shown.map((p) => (
                <tr key={p.id} className="clickable" onClick={() => setEditingId(p.id)}>
                  <td>
                    <button type="button" style={{ all: "unset", cursor: "pointer", display: "flex", flexDirection: "column" }} onClick={() => setEditingId(p.id)}>
                      <strong>{p.name}</strong>
                      {p.email && <span className="muted" style={{ fontSize: 12 }}>{p.email}</span>}
                    </button>
                  </td>
                  <td><DomainTag person={p} customers={ctx.customers} /></td>
                  <td>
                    {!p.panel ? <span className="muted">Sem acesso</span> : (
                      <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                        <span className="mono" style={{ fontSize: 12.5 }}>{p.panel.login}</span>
                        <span className="muted" style={{ fontSize: 12 }}>
                          {[typeName(p.panel.access_type_id), ...p.panel.group_ids.map((g) => ctx.groups.find((x) => x.id === g)?.name).filter(Boolean).map((n) => "grupo " + n)].filter(Boolean).join(" · ") || "Sem tipo nem grupo"}
                          {!p.panel.active && " · desativado"}{!p.panel.totp_enabled && " · TOTP pendente"}
                        </span>
                      </span>
                    )}
                  </td>
                  <td>
                    {!p.device ? <span className="muted">Sem acesso</span> : (
                      <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                        <span className="mono" style={{ fontSize: 12.5 }}>{p.device.username}</span>
                        <span className="muted" style={{ fontSize: 12 }}>{!p.device.active ? "Desativado" : p.device.totp_configured ? "TOTP configurado" : "Sem TOTP"}</span>
                      </span>
                    )}
                  </td>
                  <td>{p.active ? <span className="pill pill-ok">Ativa</span> : <span className="pill pill-err">Desativada</span>}</td>
                </tr>
              ))}
              {shown.length === 0 && <tr><td colSpan={5} className="muted">Nenhuma pessoa encontrada.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      {creating && <CreateDialog ctx={ctx} onClose={() => setCreating(false)} onCreated={(p) => { setCreating(false); setList((l) => [...l, p]); setEditingId(p.id); }} />}
      {editing && <PersonDialog person={editing} ctx={ctx} onChange={replace} onClose={() => { setEditingId(null); void load(); }} />}
    </>
  );
}

function Dialog({ title, onClose, wide, children }: { title: ReactNode; onClose: () => void; wide?: boolean; children: ReactNode }) {
  return (
    <div className="overlay" role="dialog" aria-modal="true" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="card dialog" style={wide ? { maxWidth: 960 } : undefined}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2 style={{ fontSize: 18 }}>{title}</h2>
          <button type="button" className="btn btn-icon" onClick={onClose} aria-label="Fechar"><Icon name="x" /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

function CreateDialog({ ctx, onClose, onCreated }: { ctx: Ctx; onClose: () => void; onCreated: (p: Person) => void }) {
  const { can } = useAuth();
  const domains = [
    ...(can("admin.people.edit") ? [{ id: "", label: `@${GLOBAL_DOMAIN} (equipe global)` }] : []),
    ...ctx.customers.filter((c) => can("admin.people.edit", c.id)).map((c) => ({ id: c.id, label: `@${c.domain} (${c.code} · ${c.name})` })),
  ];
  const [f, setF] = useState({ name: "", email: "", phone: "", customer_id: domains[0]?.id ?? "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      onCreated(await api.post<Person>("/api/people", { ...f, customer_id: f.customer_id || null }));
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog title="Nova pessoa" onClose={onClose}>
      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <div className="form-grid">
          <label className="field"><span>Nome</span><input className="input" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
          <label className="field">
            <span>Domínio</span>
            <select className="input" value={f.customer_id} onChange={(e) => setF({ ...f, customer_id: e.target.value })}>
              {domains.map((d) => <option key={d.id} value={d.id}>{d.label}</option>)}
            </select>
            <small>Não pode ser trocado depois: faz parte do login.</small>
          </label>
          <label className="field"><span>E-mail de contato</span><input className="input" type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
          <label className="field"><span>Telefone</span><input className="input" value={f.phone} onChange={(e) => setF({ ...f, phone: e.target.value })} /></label>
        </div>
        {error && <div className="alert alert-err" role="alert">{error}</div>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn" onClick={onClose}>Cancelar</button>
          <button className="btn btn-primary" disabled={busy || domains.length === 0}>Cadastrar</button>
        </div>
      </form>
    </Dialog>
  );
}

function Section({ title, desc, children }: { title: string; desc?: string; children: ReactNode }) {
  return (
    <section style={{ display: "flex", flexDirection: "column", gap: 14, paddingTop: 18, borderTop: "1px solid var(--border)" }}>
      <div>
        <h2>{title}</h2>
        {desc && <p className="muted" style={{ margin: "4px 0 0", fontSize: 13 }}>{desc}</p>}
      </div>
      {children}
    </section>
  );
}

function useAction() {
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<void>, okText: string) => {
    setBusy(true);
    setMsg(null);
    try {
      await fn();
      setMsg({ ok: true, text: okText });
    } catch (e) {
      setMsg({ ok: false, text: errMsg(e) });
    } finally {
      setBusy(false);
    }
  };
  const view = msg && <div className={"alert " + (msg.ok ? "alert-ok" : "alert-err")} role={msg.ok ? "status" : "alert"}>{msg.text}</div>;
  return { run, busy, view };
}

function LoginField({ label, value, onChange, domain }: { label: string; value: string; onChange: (v: string) => void; domain: string }) {
  return (
    <label className="field">
      <span>{label}</span>
      <span style={{ display: "flex", alignItems: "stretch" }}>
        <input className="input mono" required value={value} onChange={(e) => onChange(e.target.value.toLowerCase())} style={{ borderTopRightRadius: 0, borderBottomRightRadius: 0 }} />
        <span className="mono" style={{ display: "flex", alignItems: "center", padding: "0 10px", border: "1px solid var(--border)", borderLeft: 0, borderRadius: "0 10px 10px 0", background: "var(--sunk)", color: "var(--muted)", fontSize: 13, whiteSpace: "nowrap" }}>@{domain}</span>
      </span>
    </label>
  );
}

function PersonDialog({ person, ctx, onChange, onClose }: { person: Person; ctx: Ctx; onChange: (p: Person) => void; onClose: () => void }) {
  const { me, can } = useAuth();
  const scope = person.customer_id ?? undefined;
  const canEdit = can("admin.people.edit", scope);
  return (
    <Dialog wide onClose={onClose} title={<span className="row" style={{ gap: 10 }}>{person.name} <DomainTag person={person} customers={ctx.customers} /></span>}>
      <PersonData person={person} self={me?.id === person.id} canEdit={canEdit} onChange={onChange} />
      <PanelSection person={person} self={me?.id === person.id} ctx={ctx} onChange={onChange} />
      <DeviceSection person={person} onChange={onChange} />
    </Dialog>
  );
}

function PersonData({ person, self, canEdit, onChange }: { person: Person; self: boolean; canEdit: boolean; onChange: (p: Person) => void }) {
  const [f, setF] = useState({ name: person.name, email: person.email ?? "", phone: person.phone ?? "", active: person.active });
  const a = useAction();
  return (
    <form style={{ display: "flex", flexDirection: "column", gap: 14 }}
      onSubmit={(e) => { e.preventDefault(); void a.run(async () => onChange(await api.patch<Person>(`/api/people/${person.id}`, f)), "Dados salvos."); }}>
      <div className="form-grid">
        <label className="field"><span>Nome</span><input className="input" required disabled={!canEdit} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
        <label className="field"><span>E-mail de contato</span><input className="input" type="email" disabled={!canEdit} value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
        <label className="field"><span>Telefone</span><input className="input" disabled={!canEdit} value={f.phone} onChange={(e) => setF({ ...f, phone: e.target.value })} /></label>
      </div>
      {canEdit && (
        <div className="row" style={{ justifyContent: "space-between" }}>
          <label className="row" style={{ cursor: self ? "not-allowed" : "pointer" }}>
            <input type="checkbox" disabled={self} checked={f.active} onChange={(e) => setF({ ...f, active: e.target.checked })} style={{ width: 18, height: 18 }} />
            Pessoa ativa <span className="muted" style={{ fontSize: 12.5 }}>(desativar bloqueia os dois acessos)</span>
          </label>
          <button className="btn" disabled={a.busy}>Salvar dados</button>
        </div>
      )}
      {a.view}
    </form>
  );
}

function PanelSection({ person, self, ctx, onChange }: { person: Person; self: boolean; ctx: Ctx; onChange: (p: Person) => void }) {
  const { me, can } = useAuth();
  const panel = person.panel;
  const scope = person.customer_id ?? undefined;
  const canEdit = can("admin.people.edit", scope);
  const isCustomerDomain = !!person.customer_id;
  const [enabled, setEnabled] = useState(!!panel);
  const [f, setF] = useState({
    login: panel?.login.split("@")[0] ?? "", password: "", active: panel?.active ?? true,
    access_type_id: panel?.access_type_id ?? "", group_ids: panel?.group_ids ?? [], customer_ids: panel?.customer_ids ?? [],
  });
  const a = useAction();

  const typeOptions = ctx.types.filter((t) => (isCustomerDomain ? t.scope === "customer" : true) && (me?.is_admin || t.scope === "customer"));
  const groupOptions = ctx.groups.filter((g) => (isCustomerDomain ? g.customer_id === person.customer_id : g.customer_id === null));
  const selectedBases = [ctx.types.find((t) => t.id === f.access_type_id), ...f.group_ids.map((g) => ctx.types.find((t) => t.id === ctx.groups.find((x) => x.id === g)?.base_type_id))];
  const needsCustomers = !isCustomerDomain && selectedBases.some((t) => t?.scope === "customer");

  const save = (e: FormEvent) => {
    e.preventDefault();
    void a.run(async () => {
      const body: Record<string, unknown> = { login: f.login, active: f.active, access_type_id: f.access_type_id || null, group_ids: f.group_ids, customer_ids: needsCustomers ? f.customer_ids : [] };
      if (f.password) body.password = f.password;
      onChange(await api.put<Person>(`/api/people/${person.id}/panel`, body));
      setF((x) => ({ ...x, password: "" }));
    }, panel ? "Acesso ao painel salvo." : "Acesso ao painel criado. No primeiro login a pessoa cadastra o TOTP.");
  };
  const remove = () => {
    if (!confirm(`Remover o acesso de ${person.name} ao painel?`)) return;
    void a.run(async () => { onChange(await api.del<Person>(`/api/people/${person.id}/panel`)); setEnabled(false); }, "Acesso ao painel removido.");
  };
  const resetTotp = () => {
    if (!confirm(`Redefinir o TOTP do painel de ${person.name}? As sessões serão encerradas.`)) return;
    void a.run(async () => onChange(await api.post<Person>(`/api/people/${person.id}/panel/reset-totp`)), "TOTP do painel redefinido.");
  };
  const toggle = (list: string[], id: string, on: boolean) => (on ? [...list, id] : list.filter((x) => x !== id));

  return (
    <Section title="Acesso ao painel ONE GATE" desc="Login, senha e TOTP próprios. O que a pessoa vê e faz vem do tipo de acesso, dos grupos e das exceções.">
      <label className="row" style={{ cursor: panel || !canEdit ? "default" : "pointer" }}>
        <input type="checkbox" checked={enabled} disabled={!!panel || !canEdit} onChange={(e) => setEnabled(e.target.checked)} style={{ width: 18, height: 18 }} />
        Pode acessar o ONE GATE
      </label>
      {enabled && (
        <form onSubmit={save} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div className="form-grid">
            <LoginField label="Login" value={f.login} onChange={(v) => setF({ ...f, login: v })} domain={person.domain} />
            <label className="field">
              <span>{panel ? "Nova senha (opcional)" : "Senha inicial"}</span>
              <input className="input" type="password" autoComplete="new-password" minLength={12} required={!panel} disabled={!canEdit} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
              <small>Mínimo 12 caracteres. Diferente da senha dos equipamentos.</small>
            </label>
            <label className="field">
              <span>Tipo de acesso</span>
              <select className="input" disabled={!canEdit || self} value={f.access_type_id} onChange={(e) => setF({ ...f, access_type_id: e.target.value })}>
                <option value="">Nenhum (só pelos grupos)</option>
                {typeOptions.map((t) => <option key={t.id} value={t.id}>{t.name} ({t.scope === "global" ? "global" : "por cliente"})</option>)}
              </select>
              {self && <small>Você não pode alterar as próprias permissões.</small>}
            </label>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <strong style={{ fontSize: 13.5 }}>Grupos</strong>
            <div className="row" style={{ gap: 14 }}>
              {groupOptions.map((g) => (
                <label key={g.id} className="row" style={{ gap: 6, cursor: "pointer" }}>
                  <input type="checkbox" disabled={!canEdit || self} checked={f.group_ids.includes(g.id)} onChange={(e) => setF({ ...f, group_ids: toggle(f.group_ids, g.id, e.target.checked) })} style={{ width: 18, height: 18 }} />
                  {g.name} <span className="muted" style={{ fontSize: 12 }}>({ctx.types.find((t) => t.id === g.base_type_id)?.name})</span>
                </label>
              ))}
              {groupOptions.length === 0 && <span className="muted">Nenhum grupo neste domínio. Crie em Permissões.</span>}
            </div>
          </div>
          {needsCustomers && (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <strong style={{ fontSize: 13.5 }}>Clientes atribuídos <span className="muted" style={{ fontWeight: 400 }}>(para os tipos de escopo por cliente)</span></strong>
              <div className="row" style={{ gap: 14 }}>
                {ctx.customers.map((c) => (
                  <label key={c.id} className="row" style={{ gap: 6, cursor: "pointer" }}>
                    <input type="checkbox" disabled={!canEdit || self} checked={f.customer_ids.includes(c.id)} onChange={(e) => setF({ ...f, customer_ids: toggle(f.customer_ids, c.id, e.target.checked) })} style={{ width: 18, height: 18 }} />
                    <CustomerBadge code={c.code} name={c.name} color={c.color} />
                  </label>
                ))}
              </div>
            </div>
          )}
          {panel && (
            <div className="row" style={{ fontSize: 13 }}>
              <label className="row" style={{ cursor: self ? "not-allowed" : "pointer" }}>
                <input type="checkbox" disabled={self || !canEdit} checked={f.active} onChange={(e) => setF({ ...f, active: e.target.checked })} style={{ width: 18, height: 18 }} />
                Acesso ativo
              </label>
              <span className={"pill " + (panel.totp_enabled ? "pill-ok" : "pill-warn")}>{panel.totp_enabled ? "TOTP ativo" : "TOTP pendente"}</span>
              <span className="muted">Último login: {formatDate(panel.last_login_at)}</span>
            </div>
          )}
          <div className="row" style={{ justifyContent: "space-between" }}>
            <div className="row">
              {panel && !self && canEdit && <button type="button" className="btn btn-danger" onClick={remove} disabled={a.busy}>Remover acesso</button>}
              {panel && can("admin.totp.reset", scope) && <button type="button" className="btn" onClick={resetTotp} disabled={a.busy || !panel.totp_enabled}>Redefinir TOTP</button>}
            </div>
            {canEdit && <button className="btn btn-primary" disabled={a.busy}>{panel ? "Salvar acesso ao painel" : "Criar acesso ao painel"}</button>}
          </div>
          {a.view}
        </form>
      )}
      {panel && <Overrides person={person} self={self} ctx={ctx} onChange={onChange} />}
    </Section>
  );
}

function Overrides({ person, self, ctx, onChange }: { person: Person; self: boolean; ctx: Ctx; onChange: (p: Person) => void }) {
  const { can } = useAuth();
  const canEdit = can("admin.people.edit", person.customer_id ?? undefined) && !self;
  const [ov, setOv] = useState(person.panel?.overrides ?? {});
  const scopes = person.customer_id ? ctx.customers.filter((c) => c.id === person.customer_id) : ctx.customers;
  const [scope, setScope] = useState(person.customer_id ?? "");
  const [eff, setEff] = useState<Record<string, { allowed: boolean; reason: string }>>({});
  const a = useAction();

  const loadEff = async () => {
    const list = await api.get<{ function: string; allowed: boolean; reason: string }[]>(`/api/people/${person.id}/effective${scope ? `?customer_id=${scope}` : ""}`);
    setEff(Object.fromEntries(list.map((x) => [x.function, x])));
  };
  useEffect(() => {
    void loadEff();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, person]);
  const dirty = JSON.stringify(ov) !== JSON.stringify(person.panel?.overrides ?? {});

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div>
          <strong style={{ fontSize: 14 }}>Exceções deste usuário e permissão efetiva</strong>
          <p className="muted" style={{ margin: "2px 0 0", fontSize: 12.5 }}>Exceções valem só para esta pessoa e vencem grupos e tipo. A coluna da direita mostra o resultado salvo.</p>
        </div>
        <label className="field" style={{ minWidth: 240 }}>
          <span className="sr-only">Ver permissão em</span>
          <select className="input" value={scope} onChange={(e) => setScope(e.target.value)}>
            {!person.customer_id && <option value="">Plataforma (funções gerais)</option>}
            {scopes.map((c) => <option key={c.id} value={c.id}>Cliente {c.code} · {c.name}</option>)}
          </select>
        </label>
      </div>
      <div style={{ border: "1px solid var(--border)", borderRadius: 10, padding: "0 10px" }}>
        <PermissionTree catalog={ctx.catalog} mode="overrides" overrides={ov} onOverrides={setOv} effective={eff} disabled={!canEdit} />
      </div>
      {canEdit && (
        <div className="row" style={{ justifyContent: "flex-end" }}>
          {dirty && <span className="pill pill-warn">Alterações não salvas</span>}
          <button type="button" className="btn" onClick={() => setOv(person.panel?.overrides ?? {})} disabled={!dirty}>Descartar</button>
          <button type="button" className="btn btn-primary" disabled={a.busy || !dirty}
            onClick={() => void a.run(async () => { onChange(await api.put<Person>(`/api/people/${person.id}/panel/overrides`, ov)); }, "Exceções salvas.")}>Salvar exceções</button>
        </div>
      )}
      {a.view}
    </div>
  );
}

function DeviceSection({ person, onChange }: { person: Person; onChange: (p: Person) => void }) {
  const { can } = useAuth();
  const scope = person.customer_id ?? undefined;
  const canEdit = can("aaa.users.manage", scope);
  const dev = person.device;
  const [enabled, setEnabled] = useState(!!dev);
  const [f, setF] = useState({ username: dev?.username.split("@")[0] ?? person.panel?.login.split("@")[0] ?? "", password: "", active: dev?.active ?? true });
  const [otp, setOtp] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const qr = useRef<HTMLCanvasElement>(null);
  const a = useAction();
  const b = useAction();

  useEffect(() => {
    if (otp && qr.current) void QRCode.toCanvas(qr.current, otp.otpauth_uri, { width: 180, margin: 0 });
  }, [otp]);

  const save = (e: FormEvent) => {
    e.preventDefault();
    void a.run(async () => {
      const body: Record<string, unknown> = { username: f.username, active: f.active };
      if (f.password) body.password = f.password;
      onChange(await api.put<Person>(`/api/people/${person.id}/device`, body));
      setF((x) => ({ ...x, password: "" }));
    }, dev ? "Acesso aos equipamentos salvo." : "Acesso aos equipamentos criado. Gere o TOTP.");
  };
  const remove = () => {
    if (!confirm(`Remover o acesso de ${person.name} aos equipamentos?`)) return;
    void a.run(async () => { onChange(await api.del<Person>(`/api/people/${person.id}/device`)); setEnabled(false); setOtp(null); }, "Acesso aos equipamentos removido.");
  };
  const newTotp = () => {
    if (dev?.totp_configured && !confirm("Gerar um novo TOTP? O código atual deixa de valer nos equipamentos.")) return;
    void b.run(async () => {
      setOtp(await api.post(`/api/people/${person.id}/device/totp`));
      onChange({ ...person, device: dev && { ...dev, totp_configured: true } });
    }, "Novo TOTP gerado. Cadastre no app autenticador agora: ele não será mostrado de novo.");
  };

  return (
    <Section title="Acesso aos equipamentos (usuário AAA)" desc="Usuário, senha e TOTP próprios, usados via TACACS+/RADIUS. Onde e o que a pessoa pode fazer é definido nas Regras de acesso AAA.">
      <label className="row" style={{ cursor: dev || !canEdit ? "default" : "pointer" }}>
        <input type="checkbox" checked={enabled} disabled={!!dev || !canEdit} onChange={(e) => setEnabled(e.target.checked)} style={{ width: 18, height: 18 }} />
        Pode acessar os equipamentos
      </label>
      {enabled && (
        <form onSubmit={save} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div className="form-grid">
            <LoginField label="Usuário nos equipamentos" value={f.username} onChange={(v) => setF({ ...f, username: v })} domain={person.domain} />
            <label className="field">
              <span>{dev ? "Nova senha (opcional)" : "Senha"}</span>
              <input className="input" type="password" autoComplete="new-password" minLength={12} required={!dev} disabled={!canEdit} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
              <small>{dev ? `Alterada em ${formatDate(dev.password_changed_at)}.` : "Mínimo 12 caracteres. Diferente da senha do painel."}</small>
            </label>
          </div>
          <span className="muted" style={{ fontSize: 12.5 }}>No equipamento a pessoa pode digitar só <span className="mono">{f.username || "usuario"}</span>: o Edge completa o domínio.</span>
          {dev && (
            <label className="row" style={{ cursor: "pointer" }}>
              <input type="checkbox" disabled={!canEdit} checked={f.active} onChange={(e) => setF({ ...f, active: e.target.checked })} style={{ width: 18, height: 18 }} />
              Acesso ativo
            </label>
          )}
          {canEdit && (
            <div className="row" style={{ justifyContent: "space-between" }}>
              <div>{dev && <button type="button" className="btn btn-danger" onClick={remove} disabled={a.busy}>Remover acesso</button>}</div>
              <button className="btn btn-primary" disabled={a.busy}>{dev ? "Salvar acesso aos equipamentos" : "Criar acesso aos equipamentos"}</button>
            </div>
          )}
          {a.view}
        </form>
      )}
      {dev && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <span className="row"><strong style={{ fontSize: 14 }}>TOTP dos equipamentos</strong>
              <span className={"pill " + (dev.totp_configured ? "pill-ok" : "pill-warn")}>{dev.totp_configured ? "Configurado" : "Não configurado"}</span></span>
            {can("aaa.users.totp", scope) && <button type="button" className="btn" onClick={newTotp} disabled={b.busy}>{dev.totp_configured ? "Gerar novo TOTP" : "Gerar TOTP"}</button>}
          </div>
          {otp && (
            <div className="row" style={{ alignItems: "flex-start", gap: 16, padding: 14, borderRadius: 10, background: "var(--sunk)" }}>
              <canvas ref={qr} className="qr" aria-label="QR Code do TOTP dos equipamentos" />
              <div style={{ display: "flex", flexDirection: "column", gap: 6, flex: "1 1 240px" }}>
                <span>Entregue à pessoa para ler no app autenticador. Aparece como <strong>ONE GATE (equipamentos)</strong>.</span>
                <span className="muted" style={{ fontSize: 12.5 }}>Segredo para digitar manualmente:</span>
                <span className="mono" style={{ wordBreak: "break-all" }}>{otp.secret}</span>
              </div>
            </div>
          )}
          {b.view}
        </div>
      )}
    </Section>
  );
}
