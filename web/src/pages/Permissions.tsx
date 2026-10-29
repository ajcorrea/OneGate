import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, ApiError, GLOBAL_DOMAIN, type AccessType, type CatalogMenu, type Customer, type Decision, type PanelGroup, type Person } from "../api";
import { useAuth } from "../auth";
import { CustomerBadge } from "../components/CustomerBadge";
import { Icon } from "../components/Icon";
import { PermissionTree } from "../components/PermissionTree";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : "Erro inesperado.";
}

type Tab = "types" | "groups" | "simulate";

export function Permissions() {
  const [tab, setTab] = useState<Tab>("types");
  const [types, setTypes] = useState<AccessType[]>([]);
  const [groups, setGroups] = useState<PanelGroup[]>([]);
  const [catalog, setCatalog] = useState<CatalogMenu[]>([]);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [people, setPeople] = useState<Person[]>([]);
  const [error, setError] = useState("");

  const load = async () => {
    try {
      const [t, g, c, cu, p] = await Promise.all([
        api.get<AccessType[]>("/api/access-types"), api.get<PanelGroup[]>("/api/panel-groups"), api.get<CatalogMenu[]>("/api/permissions/catalog"),
        api.get<Customer[]>("/api/customers"), api.get<Person[]>("/api/people"),
      ]);
      setTypes(t);
      setGroups(g);
      setCatalog(c);
      setCustomers(cu);
      setPeople(p);
    } catch (e) {
      setError(errMsg(e));
    }
  };
  useEffect(() => {
    void load();
  }, []);

  const tabs: [Tab, string, number][] = [["types", "Tipos de acesso", types.length], ["groups", "Grupos", groups.length], ["simulate", "Simulador", people.filter((p) => p.panel).length]];
  return (
    <>
      <div className="page-head">
        <div style={{ maxWidth: 780 }}>
          <h1>Permissões do painel</h1>
          <p>Cada função do sistema é um item da árvore. A permissão vem do <strong>tipo de acesso</strong>, pode ser ajustada no <strong>grupo</strong> e, por último, no <strong>usuário</strong> (em Pessoas e acessos). Ordem: usuário → grupos (negar vence) → tipo.</p>
        </div>
      </div>
      {error && <div className="alert alert-err">{error}</div>}
      <div role="tablist" style={{ display: "flex", flexWrap: "wrap", borderBottom: "1px solid var(--border)" }}>
        {tabs.map(([id, label, n]) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id} onClick={() => setTab(id)}
            style={{ minHeight: 44, padding: "0 4px", marginRight: 22, border: 0, borderBottom: `2px solid ${tab === id ? "var(--accent)" : "transparent"}`, background: "transparent", font: "inherit", cursor: "pointer", fontWeight: tab === id ? 600 : 500, color: tab === id ? "var(--text)" : "var(--muted)" }}>
            {label} <span className="muted" style={{ fontWeight: 500 }}>· {n}</span>
          </button>
        ))}
      </div>
      {tab === "types" && <TypesTab types={types} catalog={catalog} reload={load} />}
      {tab === "groups" && <GroupsTab groups={groups} types={types} catalog={catalog} customers={customers} people={people} reload={load} />}
      {tab === "simulate" && <SimulateTab people={people} customers={customers} catalog={catalog} />}
    </>
  );
}

function ListItem({ on, title, tag, sub, onClick }: { on: boolean; title: string; tag: React.ReactNode; sub: string; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick}
      style={{ display: "flex", flexDirection: "column", gap: 4, padding: "10px 12px", borderRadius: 10, font: "inherit", color: "var(--text)", cursor: "pointer", textAlign: "left", border: `1px solid ${on ? "var(--accent)" : "transparent"}`, background: on ? "var(--accent-soft)" : "transparent" }}>
      <span className="row" style={{ justifyContent: "space-between", width: "100%" }}><strong>{title}</strong>{tag}</span>
      <span className="muted" style={{ fontSize: 12 }}>{sub}</span>
    </button>
  );
}

function TypesTab({ types, catalog, reload }: { types: AccessType[]; catalog: CatalogMenu[]; reload: () => Promise<void> }) {
  const { me } = useAuth();
  const [selId, setSelId] = useState(types[0]?.id ?? "");
  const sel = types.find((t) => t.id === selId) ?? types[0];
  const [grants, setGrants] = useState<Set<string>>(new Set(sel?.grants ?? []));
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [creating, setCreating] = useState(false);
  useEffect(() => setGrants(new Set(sel?.grants ?? [])), [sel?.id, sel?.grants]);
  if (!sel) return null;
  const editable = !!me?.is_admin && !sel.full_access;
  const dirty = JSON.stringify([...grants].sort()) !== JSON.stringify([...sel.grants].sort());

  const save = async () => {
    setMsg(null);
    try {
      await api.put(`/api/access-types/${sel.id}/grants`, [...grants]);
      await reload();
      setMsg({ ok: true, text: "Funções do tipo salvas. Valem para todas as pessoas e grupos que usam este tipo." });
    } catch (e) {
      setMsg({ ok: false, text: errMsg(e) });
    }
  };

  return (
    <div className="row" style={{ alignItems: "flex-start", gap: 16 }}>
      <section className="card" style={{ flex: "1 1 260px", padding: 10, display: "flex", flexDirection: "column", gap: 4 }}>
        {types.map((t) => (
          <ListItem key={t.id} on={t.id === sel.id} onClick={() => { setSelId(t.id); setMsg(null); }} title={t.name}
            tag={<span className={"pill " + (t.scope === "global" ? "pill-info" : "pill-ok")}>{t.scope === "global" ? "Global" : "Por cliente"}</span>}
            sub={(t.builtin ? "Pronto · " : "Personalizado · ") + (t.full_access ? "todas as funções" : `${t.grants.length} funções`)} />
        ))}
        {me?.is_admin && <button type="button" className="btn" style={{ borderStyle: "dashed", color: "var(--accent-text)" }} onClick={() => setCreating(true)}>+ Novo tipo de acesso</button>}
      </section>
      <section className="card" style={{ flex: "3 1 560px", minWidth: 0 }}>
        <div className="row card-pad" style={{ justifyContent: "space-between", paddingBottom: 10, borderBottom: "1px solid var(--border)" }}>
          <div>
            <h2>{sel.name}</h2>
            <p className="muted" style={{ margin: "2px 0 0", fontSize: 12.5 }}>{sel.description || (sel.scope === "global" ? "Escopo global: todos os clientes." : "Escopo por cliente: só nos clientes da pessoa.")}</p>
          </div>
          {editable && (
            <div className="row">
              {dirty && <span className="pill pill-warn">Alterações não salvas</span>}
              <button className="btn" disabled={!dirty} onClick={() => setGrants(new Set(sel.grants))}>Descartar</button>
              <button className="btn btn-primary" disabled={!dirty} onClick={() => void save()}>Salvar</button>
            </div>
          )}
        </div>
        {sel.full_access && <div className="alert" style={{ margin: "14px 20px 0", background: "var(--accent-soft)", color: "var(--accent-text)" }}>O Admin global tem todas as funções em todos os clientes e não pode ser restringido.</div>}
        {!me?.is_admin && <div className="alert alert-warn" style={{ margin: "14px 20px 0" }}>Só o Admin global altera tipos de acesso.</div>}
        {msg && <div className={"alert " + (msg.ok ? "alert-ok" : "alert-err")} style={{ margin: "14px 20px 0" }}>{msg.text}</div>}
        <div style={{ padding: "4px 16px 16px" }}>
          <PermissionTree catalog={catalog} mode="grants" grants={grants} onGrants={setGrants} disabled={!editable} customerScope={sel.scope === "customer"} />
        </div>
      </section>
      {creating && <NewTypeDialog types={types} onClose={() => setCreating(false)} onCreated={async (id) => { setCreating(false); await reload(); setSelId(id); }} />}
    </div>
  );
}

function NewTypeDialog({ types, onClose, onCreated }: { types: AccessType[]; onClose: () => void; onCreated: (id: string) => void }) {
  const [f, setF] = useState({ name: "", description: "", scope: "customer", copy_from: "" });
  const [error, setError] = useState("");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const r = await api.post<{ id: string }>("/api/access-types", { ...f, copy_from: f.copy_from || null });
      onCreated(r.id);
    } catch (err) {
      setError(errMsg(err));
    }
  };
  return (
    <div className="overlay" role="dialog" aria-modal="true" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <form className="card dialog" onSubmit={submit}>
        <div className="row" style={{ justifyContent: "space-between" }}><h2 style={{ fontSize: 18 }}>Novo tipo de acesso</h2><button type="button" className="btn btn-icon" aria-label="Fechar" onClick={onClose}><Icon name="x" /></button></div>
        <div className="form-grid">
          <label className="field"><span>Nome</span><input className="input" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
          <label className="field">
            <span>Escopo</span>
            <select className="input" value={f.scope} onChange={(e) => setF({ ...f, scope: e.target.value })}>
              <option value="customer">Por cliente (só nos clientes da pessoa)</option>
              <option value="global">Global (todos os clientes)</option>
            </select>
          </label>
          <label className="field">
            <span>Copiar funções de</span>
            <select className="input" value={f.copy_from} onChange={(e) => setF({ ...f, copy_from: e.target.value })}>
              <option value="">Começar vazio</option>
              {types.filter((t) => !t.full_access).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </label>
        </div>
        <label className="field"><span>Descrição</span><input className="input" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
        {error && <div className="alert alert-err">{error}</div>}
        <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" className="btn" onClick={onClose}>Cancelar</button><button className="btn btn-primary">Criar</button></div>
      </form>
    </div>
  );
}

function GroupsTab({ groups, types, catalog, customers, people, reload }: { groups: PanelGroup[]; types: AccessType[]; catalog: CatalogMenu[]; customers: Customer[]; people: Person[]; reload: () => Promise<void> }) {
  const { me, can } = useAuth();
  const [selId, setSelId] = useState(groups[0]?.id ?? "");
  const sel = groups.find((g) => g.id === selId) ?? groups[0];
  const [ov, setOv] = useState<Record<string, "allow" | "deny">>(sel?.overrides ?? {});
  const [base, setBase] = useState(sel?.base_type_id ?? "");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [creating, setCreating] = useState(false);
  useEffect(() => { setOv(sel?.overrides ?? {}); setBase(sel?.base_type_id ?? ""); }, [sel?.id, sel?.overrides, sel?.base_type_id]);
  const cust = (id: string | null) => customers.find((c) => c.id === id);
  const canCreate = can("admin.people.edit") || customers.some((c) => can("admin.people.edit", c.id));

  const baseType = types.find((t) => t.id === base);
  const effective = useMemo(() => {
    // Prévia do grupo: exceção do grupo, senão o tipo base.
    const out: Record<string, { allowed: boolean; reason: string }> = {};
    for (const m of catalog) for (const f of m.functions) {
      const v = ov[f.id];
      if (v) out[f.id] = { allowed: v === "allow", reason: (v === "allow" ? "Permitido" : "Negado") + " neste grupo" };
      else out[f.id] = { allowed: !!baseType?.full_access || !!baseType?.grants.includes(f.id), reason: "Herdado do tipo " + (baseType?.name ?? "—") };
    }
    return out;
  }, [ov, baseType, catalog]);

  const empty = (
    <section className="card card-pad" style={{ flex: "3 1 560px" }}>
      <p className="muted" style={{ margin: 0 }}>Nenhum grupo ainda. Grupos ajustam um tipo de acesso para um conjunto de pessoas (ex.: NOC, Suporte N1).</p>
    </section>
  );
  const editable = !!sel && can("admin.people.edit", sel.customer_id ?? undefined) && !(sel.members.includes(me?.id ?? "") && !me?.is_admin);
  const dirty = !!sel && (JSON.stringify(ov) !== JSON.stringify(sel.overrides) || base !== sel.base_type_id);
  const save = async () => {
    if (!sel) return;
    setMsg(null);
    try {
      if (base !== sel.base_type_id) await api.patch(`/api/panel-groups/${sel.id}`, { base_type_id: base });
      await api.put(`/api/panel-groups/${sel.id}/overrides`, ov);
      await reload();
      setMsg({ ok: true, text: "Grupo salvo." });
    } catch (e) {
      setMsg({ ok: false, text: errMsg(e) });
    }
  };
  const remove = async () => {
    if (!sel || !confirm(`Excluir o grupo ${sel.name}? Os membros perdem as permissões vindas dele.`)) return;
    try {
      await api.del(`/api/panel-groups/${sel.id}`);
      await reload();
    } catch (e) {
      setMsg({ ok: false, text: errMsg(e) });
    }
  };

  return (
    <div className="row" style={{ alignItems: "flex-start", gap: 16 }}>
      <section className="card" style={{ flex: "1 1 260px", padding: 10, display: "flex", flexDirection: "column", gap: 4 }}>
        {groups.map((g) => {
          const c = cust(g.customer_id);
          return (
            <ListItem key={g.id} on={g.id === sel?.id} onClick={() => { setSelId(g.id); setMsg(null); }} title={g.name}
              tag={c ? <CustomerBadge code={c.code} name={"@" + c.domain} color={c.color} /> : <span className="pill pill-info">@{GLOBAL_DOMAIN}</span>}
              sub={`Base: ${types.find((t) => t.id === g.base_type_id)?.name ?? "—"} · ${g.members.length} membro(s)`} />
          );
        })}
        {canCreate && <button type="button" className="btn" style={{ borderStyle: "dashed", color: "var(--accent-text)" }} onClick={() => setCreating(true)}>+ Novo grupo</button>}
      </section>
      {!sel ? empty : (
        <section className="card" style={{ flex: "3 1 560px", minWidth: 0 }}>
          <div className="row card-pad" style={{ justifyContent: "space-between", paddingBottom: 10, borderBottom: "1px solid var(--border)" }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <h2>{sel.name}</h2>
              <label className="row" style={{ gap: 8, fontSize: 13 }}>
                Tipo base
                <select className="input" style={{ minHeight: 36, width: 260 }} disabled={!editable} value={base} onChange={(e) => setBase(e.target.value)}>
                  {types.filter((t) => (sel.customer_id ? t.scope === "customer" : true) && (me?.is_admin || t.scope === "customer")).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                </select>
              </label>
              <span className="muted" style={{ fontSize: 12.5 }}>Membros: {sel.members.map((m) => people.find((p) => p.id === m)?.name ?? "—").join(", ") || "nenhum (adicione em Pessoas e acessos)"}</span>
            </div>
            {editable && (
              <div className="row">
                {dirty && <span className="pill pill-warn">Alterações não salvas</span>}
                <button className="btn btn-danger" onClick={() => void remove()}>Excluir</button>
                <button className="btn btn-primary" disabled={!dirty} onClick={() => void save()}>Salvar</button>
              </div>
            )}
          </div>
          {!editable && <div className="alert alert-warn" style={{ margin: "14px 20px 0" }}>Somente leitura: você não pode alterar este grupo.</div>}
          {msg && <div className={"alert " + (msg.ok ? "alert-ok" : "alert-err")} style={{ margin: "14px 20px 0" }}>{msg.text}</div>}
          <div style={{ padding: "4px 16px 16px" }}>
            <PermissionTree catalog={catalog} mode="overrides" overrides={ov} onOverrides={setOv} effective={effective} disabled={!editable} customerScope={!!sel.customer_id} />
          </div>
        </section>
      )}
      {creating && <NewGroupDialog types={types} customers={customers} onClose={() => setCreating(false)} onCreated={async (id) => { setCreating(false); await reload(); setSelId(id); }} />}
    </div>
  );
}

function NewGroupDialog({ types, customers, onClose, onCreated }: { types: AccessType[]; customers: Customer[]; onClose: () => void; onCreated: (id: string) => void }) {
  const { me, can } = useAuth();
  const scopes = [
    ...(can("admin.people.edit") ? [{ id: "", label: `@${GLOBAL_DOMAIN} (grupo global)` }] : []),
    ...customers.filter((c) => can("admin.people.edit", c.id)).map((c) => ({ id: c.id, label: `@${c.domain} (${c.code})` })),
  ];
  const [f, setF] = useState({ name: "", description: "", customer_id: scopes[0]?.id ?? "", base_type_id: "" });
  const baseOptions = types.filter((t) => (f.customer_id ? t.scope === "customer" : true) && (me?.is_admin || t.scope === "customer"));
  const [error, setError] = useState("");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const r = await api.post<{ id: string }>("/api/panel-groups", { ...f, customer_id: f.customer_id || null, base_type_id: f.base_type_id || baseOptions[0]?.id });
      onCreated(r.id);
    } catch (err) {
      setError(errMsg(err));
    }
  };
  return (
    <div className="overlay" role="dialog" aria-modal="true" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <form className="card dialog" onSubmit={submit}>
        <div className="row" style={{ justifyContent: "space-between" }}><h2 style={{ fontSize: 18 }}>Novo grupo</h2><button type="button" className="btn btn-icon" aria-label="Fechar" onClick={onClose}><Icon name="x" /></button></div>
        <div className="form-grid">
          <label className="field"><span>Nome</span><input className="input" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
          <label className="field">
            <span>Domínio do grupo</span>
            <select className="input" value={f.customer_id} onChange={(e) => setF({ ...f, customer_id: e.target.value, base_type_id: "" })}>
              {scopes.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
          </label>
          <label className="field">
            <span>Tipo base</span>
            <select className="input" value={f.base_type_id || baseOptions[0]?.id || ""} onChange={(e) => setF({ ...f, base_type_id: e.target.value })}>
              {baseOptions.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </label>
        </div>
        <label className="field"><span>Descrição</span><input className="input" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
        {error && <div className="alert alert-err">{error}</div>}
        <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" className="btn" onClick={onClose}>Cancelar</button><button className="btn btn-primary">Criar</button></div>
      </form>
    </div>
  );
}

function SimulateTab({ people, customers, catalog }: { people: Person[]; customers: Customer[]; catalog: CatalogMenu[] }) {
  const withPanel = people.filter((p) => p.panel);
  const [q, setQ] = useState("");
  const [personId, setPersonId] = useState(withPanel[0]?.id ?? "");
  const [customerId, setCustomerId] = useState(customers[0]?.id ?? "");
  const [fn, setFn] = useState("commands.run");
  const [d, setD] = useState<Decision | null>(null);
  const [error, setError] = useState("");
  const person = withPanel.find((p) => p.id === personId);
  const found = q.trim().length >= 3 ? withPanel.filter((p) => (p.name + " " + p.panel!.login).toLowerCase().includes(q.trim().toLowerCase())).slice(0, 6) : [];

  useEffect(() => {
    if (!personId) return;
    setError("");
    api.post<Decision>("/api/permissions/simulate", { person_id: personId, customer_id: customerId, function: fn }).then(setD).catch((e) => setError(errMsg(e)));
  }, [personId, customerId, fn]);

  return (
    <div className="row" style={{ alignItems: "flex-start", gap: 16 }}>
      <section className="card card-pad" style={{ flex: "1 1 340px", display: "flex", flexDirection: "column", gap: 12 }}>
        <label className="field">
          <span>Pessoa</span>
          <input className="input" type="search" placeholder="Digite 3 letras do nome ou login" value={q} onChange={(e) => setQ(e.target.value)} />
          <small>Selecionado: {person ? `${person.name} · ${person.panel?.login}` : "ninguém"}</small>
        </label>
        {found.map((p) => (
          <button key={p.id} type="button" className="btn" style={{ justifyContent: "flex-start", fontWeight: 500 }} onClick={() => { setPersonId(p.id); setQ(""); }}>
            {p.name} <span className="muted mono" style={{ fontSize: 12 }}>{p.panel?.login}</span>
          </button>
        ))}
        <label className="field">
          <span>Onde</span>
          <select className="input" value={customerId} onChange={(e) => setCustomerId(e.target.value)}>
            <option value="">Plataforma (funções gerais)</option>
            {customers.map((c) => <option key={c.id} value={c.id}>Cliente {c.code} · {c.name}</option>)}
          </select>
        </label>
        <label className="field">
          <span>Função</span>
          <select className="input" value={fn} onChange={(e) => setFn(e.target.value)}>
            {catalog.map((m) => (
              <optgroup key={m.id} label={m.label}>
                {m.functions.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
              </optgroup>
            ))}
          </select>
        </label>
      </section>
      <section className="card card-pad" style={{ flex: "1 1 340px", display: "flex", flexDirection: "column", gap: 12 }}>
        <h2>Resultado</h2>
        {error && <div className="alert alert-err">{error}</div>}
        {d && (
          <>
            <div className={"alert " + (d.allowed ? "alert-ok" : "alert-err")} style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              <strong style={{ fontSize: 18 }}>{d.allowed ? "Permitido" : "Negado"}</strong>
              <span>{d.reason}.</span>
            </div>
            <div>
              {d.chain.map((s, i) => (
                <div key={i} className="row" style={{ justifyContent: "space-between", padding: "7px 0", borderTop: "1px solid var(--border)", fontSize: 13 }}>
                  <span className="muted">{s.level}</span><strong>{s.value}</strong>
                </div>
              ))}
            </div>
          </>
        )}
        <span className="muted" style={{ fontSize: 12 }}>Usa o que está salvo. Ordem: escopo → usuário → grupos (negar vence) → tipos.</span>
      </section>
    </div>
  );
}
