import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import QRCode from "qrcode";
import { api, ApiError, formatDate, moduleLabels, presets, type Customer, type Level, type Module, type Permission, type Person } from "../api";
import { useAuth } from "../auth";
import { CodeBox, CustomerBadge } from "../components/CustomerBadge";
import { Icon } from "../components/Icon";

const allModules: Module[] = ["aaa", "servers", "commands", "audit"];

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : "Erro inesperado.";
}

export function People() {
  const [list, setList] = useState<Person[]>([]);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  const load = async () => {
    try {
      const [p, c] = await Promise.all([api.get<Person[]>("/api/people"), api.get<Customer[]>("/api/customers")]);
      setList(p);
      setCustomers(c);
    } catch (e) {
      setError(errMsg(e));
    }
  };
  useEffect(() => {
    void load();
  }, []);

  const byId = useMemo(() => Object.fromEntries(customers.map((c) => [c.id, c])), [customers]);
  const editing = list.find((p) => p.id === editingId) ?? null;
  const replace = (p: Person) => setList((l) => l.map((x) => (x.id === p.id ? p : x)));

  const boxes = (ids: string[]) =>
    ids.length === 0 ? <span className="muted">Nenhum</span> : (
      <span className="row" style={{ gap: 4 }}>
        {ids.map((id) => byId[id] && <CodeBox key={id} code={byId[id].code} color={byId[id].color} title={byId[id].name} />)}
      </span>
    );

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Pessoas e acessos</h1>
          <p>Cada pessoa pode ter acesso ao painel ONE GATE e acesso aos equipamentos dos clientes. São credenciais separadas.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setCreating(true)}><Icon name="plus" /> Nova pessoa</button>
      </div>
      {error && <div className="alert alert-err">{error}</div>}

      <section className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Pessoa</th><th>Painel ONE GATE</th><th>Clientes no painel</th><th>Equipamentos</th><th>Clientes nos equipamentos</th><th>Situação</th></tr>
            </thead>
            <tbody>
              {list.map((p) => (
                <tr key={p.id} className="clickable" onClick={() => setEditingId(p.id)}>
                  <td>
                    <button type="button" style={{ all: "unset", cursor: "pointer", display: "flex", flexDirection: "column" }} onClick={() => setEditingId(p.id)}>
                      <strong>{p.name}</strong>
                      {p.email && <span className="muted" style={{ fontSize: 12 }}>{p.email}</span>}
                    </button>
                  </td>
                  <td>
                    {!p.panel ? <span className="muted">Sem acesso</span> : (
                      <span style={{ display: "flex", flexDirection: "column", gap: 3, alignItems: "flex-start" }}>
                        <span className={"pill " + (!p.panel.active ? "pill-err" : p.panel.is_admin ? "pill-info" : "pill-ok")}>
                          {!p.panel.active ? "Desativado" : p.panel.is_admin ? "Administrador" : "Com permissões"}
                        </span>
                        {!p.panel.totp_enabled && <span className="muted" style={{ fontSize: 11.5 }}>TOTP pendente</span>}
                      </span>
                    )}
                  </td>
                  <td>{!p.panel ? "—" : p.panel.is_admin ? <span className="muted">Todos</span> : boxes([...new Set(p.panel.permissions.map((x) => x.customer_id))])}</td>
                  <td>
                    {!p.device ? <span className="muted">Sem acesso</span> : (
                      <span style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                        <span className="mono" style={{ fontSize: 13 }}>{p.device.username}</span>
                        {!p.device.active ? <span className="pill pill-err">Desativado</span> : !p.device.totp_configured && <span className="muted" style={{ fontSize: 11.5 }}>Sem TOTP</span>}
                      </span>
                    )}
                  </td>
                  <td>{p.device ? boxes(p.device.customers) : "—"}</td>
                  <td>{p.active ? <span className="pill pill-ok">Ativa</span> : <span className="pill pill-err">Desativada</span>}</td>
                </tr>
              ))}
              {list.length === 0 && <tr><td colSpan={6} className="muted">Nenhuma pessoa cadastrada.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      {creating && (
        <CreateDialog onClose={() => setCreating(false)} onCreated={(p) => { setCreating(false); setList((l) => [...l, p]); setEditingId(p.id); }} />
      )}
      {editing && <PersonDialog person={editing} customers={customers} onChange={replace} onClose={() => { setEditingId(null); void load(); }} />}
    </>
  );
}

function Dialog({ title, onClose, wide, children }: { title: string; onClose: () => void; wide?: boolean; children: ReactNode }) {
  return (
    <div className="overlay" role="dialog" aria-modal="true" aria-label={title} onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="card dialog" style={wide ? { maxWidth: 900 } : undefined}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2 style={{ fontSize: 18 }}>{title}</h2>
          <button type="button" className="btn btn-icon" onClick={onClose} aria-label="Fechar"><Icon name="x" /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

function CreateDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (p: Person) => void }) {
  const [f, setF] = useState({ name: "", email: "", phone: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      onCreated(await api.post<Person>("/api/people", f));
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
          <label className="field"><span>E-mail</span><input className="input" type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
          <label className="field"><span>Telefone</span><input className="input" value={f.phone} onChange={(e) => setF({ ...f, phone: e.target.value })} /></label>
        </div>
        <span className="muted" style={{ fontSize: 13 }}>Depois de cadastrar, defina os acessos ao painel e aos equipamentos.</span>
        {error && <div className="alert alert-err" role="alert">{error}</div>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn" onClick={onClose}>Cancelar</button>
          <button className="btn btn-primary" disabled={busy}>Cadastrar</button>
        </div>
      </form>
    </Dialog>
  );
}

/** Seção com título, mensagem de sucesso/erro própria. */
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

function PersonDialog({ person, customers, onChange, onClose }: { person: Person; customers: Customer[]; onChange: (p: Person) => void; onClose: () => void }) {
  const { me } = useAuth();
  const self = me?.id === person.id;
  return (
    <Dialog title={person.name} onClose={onClose} wide>
      <PersonData person={person} self={self} onChange={onChange} />
      <PanelSection person={person} self={self} customers={customers} onChange={onChange} />
      <DeviceSection person={person} customers={customers} onChange={onChange} />
    </Dialog>
  );
}

function PersonData({ person, self, onChange }: { person: Person; self: boolean; onChange: (p: Person) => void }) {
  const [f, setF] = useState({ name: person.name, email: person.email ?? "", phone: person.phone ?? "", active: person.active });
  const a = useAction();
  return (
    <form style={{ display: "flex", flexDirection: "column", gap: 14 }}
      onSubmit={(e) => { e.preventDefault(); void a.run(async () => onChange(await api.patch<Person>(`/api/people/${person.id}`, f)), "Dados salvos."); }}>
      <div className="form-grid">
        <label className="field"><span>Nome</span><input className="input" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
        <label className="field"><span>E-mail</span><input className="input" type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
        <label className="field"><span>Telefone</span><input className="input" value={f.phone} onChange={(e) => setF({ ...f, phone: e.target.value })} /></label>
      </div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <label className="row" style={{ cursor: self ? "not-allowed" : "pointer" }}>
          <input type="checkbox" disabled={self} checked={f.active} onChange={(e) => setF({ ...f, active: e.target.checked })} style={{ width: 18, height: 18 }} />
          Pessoa ativa <span className="muted" style={{ fontSize: 12.5 }}>(desativar bloqueia os dois acessos)</span>
        </label>
        <button className="btn" disabled={a.busy}>Salvar dados</button>
      </div>
      {a.view}
    </form>
  );
}

function PanelSection({ person, self, customers, onChange }: { person: Person; self: boolean; customers: Customer[]; onChange: (p: Person) => void }) {
  const panel = person.panel;
  const [enabled, setEnabled] = useState(!!panel);
  const [f, setF] = useState({ login_email: panel?.login_email ?? person.email ?? "", password: "", is_admin: panel?.is_admin ?? false, active: panel?.active ?? true });
  const a = useAction();

  const save = (e: FormEvent) => {
    e.preventDefault();
    void a.run(async () => {
      const body: Record<string, unknown> = { login_email: f.login_email, is_admin: f.is_admin, active: f.active };
      if (f.password) body.password = f.password;
      onChange(await api.put<Person>(`/api/people/${person.id}/panel`, body));
      setF((x) => ({ ...x, password: "" }));
    }, panel ? "Acesso ao painel atualizado." : "Acesso ao painel criado. No primeiro login a pessoa cadastra o TOTP.");
  };
  const remove = () => {
    if (!confirm(`Remover o acesso de ${person.name} ao painel? As permissões serão apagadas.`)) return;
    void a.run(async () => { onChange(await api.del<Person>(`/api/people/${person.id}/panel`)); setEnabled(false); }, "Acesso ao painel removido.");
  };
  const resetTotp = () => {
    if (!confirm(`Redefinir o TOTP do painel de ${person.name}? As sessões serão encerradas e o app será cadastrado de novo no próximo login.`)) return;
    void a.run(async () => onChange(await api.post<Person>(`/api/people/${person.id}/panel/reset-totp`)), "TOTP do painel redefinido.");
  };

  return (
    <Section title="Acesso ao painel ONE GATE" desc="Login no painel com e-mail, senha e TOTP próprios, e permissões por cliente e módulo.">
      <label className="row" style={{ cursor: panel ? "default" : "pointer" }}>
        <input type="checkbox" checked={enabled} disabled={!!panel} onChange={(e) => setEnabled(e.target.checked)} style={{ width: 18, height: 18 }} />
        Pode acessar o ONE GATE
      </label>
      {enabled && (
        <form onSubmit={save} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div className="form-grid">
            <label className="field"><span>E-mail de login</span><input className="input" type="email" required value={f.login_email} onChange={(e) => setF({ ...f, login_email: e.target.value })} /></label>
            <label className="field">
              <span>{panel ? "Nova senha (opcional)" : "Senha inicial"}</span>
              <input className="input" type="password" autoComplete="new-password" minLength={12} required={!panel} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
              <small>Mínimo 12 caracteres. Diferente da senha dos equipamentos.</small>
            </label>
          </div>
          <div className="row">
            <label className="row" style={{ cursor: self ? "not-allowed" : "pointer" }}>
              <input type="checkbox" disabled={self} checked={f.is_admin} onChange={(e) => setF({ ...f, is_admin: e.target.checked })} style={{ width: 18, height: 18 }} />
              Administrador da plataforma <span className="muted" style={{ fontSize: 12.5 }}>(todos os clientes e cadastros)</span>
            </label>
            {panel && (
              <label className="row" style={{ cursor: self ? "not-allowed" : "pointer" }}>
                <input type="checkbox" disabled={self} checked={f.active} onChange={(e) => setF({ ...f, active: e.target.checked })} style={{ width: 18, height: 18 }} />
                Acesso ativo
              </label>
            )}
          </div>
          {panel && (
            <div className="row" style={{ fontSize: 13 }}>
              <span className={"pill " + (panel.totp_enabled ? "pill-ok" : "pill-warn")}>{panel.totp_enabled ? "TOTP ativo" : "TOTP pendente"}</span>
              <span className="muted">Último login: {formatDate(panel.last_login_at)}</span>
            </div>
          )}
          <div className="row" style={{ justifyContent: "space-between" }}>
            <div className="row">
              {panel && !self && <button type="button" className="btn btn-danger" onClick={remove} disabled={a.busy}>Remover acesso</button>}
              {panel && <button type="button" className="btn" onClick={resetTotp} disabled={a.busy || !panel.totp_enabled}>Redefinir TOTP</button>}
            </div>
            <button className="btn btn-primary" disabled={a.busy}>{panel ? "Salvar acesso ao painel" : "Criar acesso ao painel"}</button>
          </div>
          {a.view}
        </form>
      )}
      {panel && !f.is_admin && !panel.is_admin && <PermissionMatrix person={person} customers={customers} onChange={onChange} />}
    </Section>
  );
}

function PermissionMatrix({ person, customers, onChange }: { person: Person; customers: Customer[]; onChange: (p: Person) => void }) {
  const initial = () => {
    const m: Record<string, Partial<Record<Module, Level>>> = {};
    for (const p of person.panel?.permissions ?? []) (m[p.customer_id] ??= {})[p.module] = p.level;
    return m;
  };
  const [m, setM] = useState(initial);
  const a = useAction();

  const setCell = (cid: string, mod: Module, lvl: Level | "") =>
    setM((prev) => {
      const row = { ...(prev[cid] ?? {}) };
      if (lvl) row[mod] = lvl;
      else delete row[mod];
      return { ...prev, [cid]: row };
    });
  const presetOf = (cid: string) => {
    const row = m[cid] ?? {};
    return presets.find((p) => allModules.every((mod) => (p.modules[mod] ?? "") === (row[mod] ?? "")))?.id ?? "custom";
  };
  const save = () =>
    void a.run(async () => {
      const list: Permission[] = [];
      for (const [cid, row] of Object.entries(m)) for (const [mod, lvl] of Object.entries(row)) if (lvl) list.push({ customer_id: cid, module: mod as Module, level: lvl });
      onChange(await api.put<Person>(`/api/people/${person.id}/panel/permissions`, list));
    }, "Permissões salvas.");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <strong style={{ fontSize: 14 }}>Permissões por cliente</strong>
      {customers.length === 0 ? <span className="muted">Cadastre clientes primeiro.</span> : (
        <div className="table-wrap" style={{ border: "1px solid var(--border)", borderRadius: 10 }}>
          <table>
            <thead>
              <tr>
                <th>Cliente</th>
                <th>Papel</th>
                {allModules.map((mod) => <th key={mod}>{moduleLabels[mod]}</th>)}
              </tr>
            </thead>
            <tbody>
              {customers.map((c) => (
                <tr key={c.id}>
                  <td><CustomerBadge code={c.code} name={c.name} color={c.color} /></td>
                  <td>
                    <select className="input" style={{ minWidth: 170, minHeight: 36 }} aria-label={`Papel em ${c.name}`} value={presetOf(c.id)}
                      onChange={(e) => { const p = presets.find((x) => x.id === e.target.value); if (p) setM({ ...m, [c.id]: { ...p.modules } }); }}>
                      {presets.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                      <option value="custom" disabled>Personalizado</option>
                    </select>
                  </td>
                  {allModules.map((mod) => (
                    <td key={mod}>
                      <select className="input" style={{ minWidth: 110, minHeight: 36 }} aria-label={`${moduleLabels[mod]} em ${c.name}`}
                        value={m[c.id]?.[mod] ?? ""} onChange={(e) => setCell(c.id, mod, e.target.value as Level | "")}>
                        <option value="">—</option>
                        <option value="read">Ver</option>
                        {mod !== "audit" && <option value="write">{mod === "commands" ? "Executar" : "Alterar"}</option>}
                      </select>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button type="button" className="btn btn-primary" onClick={save} disabled={a.busy}>Salvar permissões</button>
      </div>
      {a.view}
    </div>
  );
}

function DeviceSection({ person, customers, onChange }: { person: Person; customers: Customer[]; onChange: (p: Person) => void }) {
  const dev = person.device;
  const [enabled, setEnabled] = useState(!!dev);
  const [f, setF] = useState({ username: dev?.username ?? "", password: "", active: dev?.active ?? true });
  const [sel, setSel] = useState<string[]>(dev?.customers ?? []);
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
    }, dev ? "Acesso aos equipamentos atualizado." : "Acesso aos equipamentos criado. Gere o TOTP e libere os clientes.");
  };
  const remove = () => {
    if (!confirm(`Remover o acesso de ${person.name} aos equipamentos de todos os clientes?`)) return;
    void a.run(async () => { onChange(await api.del<Person>(`/api/people/${person.id}/device`)); setEnabled(false); setOtp(null); }, "Acesso aos equipamentos removido.");
  };
  const newTotp = () => {
    if (dev?.totp_configured && !confirm("Gerar um novo TOTP? O código atual deixa de valer nos equipamentos.")) return;
    void b.run(async () => {
      setOtp(await api.post(`/api/people/${person.id}/device/totp`));
      onChange({ ...person, device: dev && { ...dev, totp_configured: true } });
    }, "Novo TOTP gerado. Cadastre no app autenticador agora: ele não será mostrado de novo.");
  };
  const saveCustomers = () =>
    void b.run(async () => onChange(await api.put<Person>(`/api/people/${person.id}/device/customers`, sel)), "Clientes liberados salvos.");

  return (
    <Section title="Acesso aos equipamentos dos clientes" desc="Usuário, senha e TOTP próprios, usados via TACACS+/RADIUS nos equipamentos e servidores. Não dão acesso ao painel.">
      <label className="row" style={{ cursor: dev ? "default" : "pointer" }}>
        <input type="checkbox" checked={enabled} disabled={!!dev} onChange={(e) => setEnabled(e.target.checked)} style={{ width: 18, height: 18 }} />
        Pode acessar os equipamentos
      </label>
      {enabled && (
        <form onSubmit={save} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div className="form-grid">
            <label className="field">
              <span>Usuário nos equipamentos</span>
              <input className="input mono" required value={f.username} onChange={(e) => setF({ ...f, username: e.target.value.toLowerCase() })} />
              <small>Ex.: joao.silva</small>
            </label>
            <label className="field">
              <span>{dev ? "Nova senha (opcional)" : "Senha"}</span>
              <input className="input" type="password" autoComplete="new-password" minLength={12} required={!dev} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
              <small>{dev ? `Alterada em ${formatDate(dev.password_changed_at)}.` : "Mínimo 12 caracteres. Diferente da senha do painel."}</small>
            </label>
          </div>
          {dev && (
            <label className="row" style={{ cursor: "pointer" }}>
              <input type="checkbox" checked={f.active} onChange={(e) => setF({ ...f, active: e.target.checked })} style={{ width: 18, height: 18 }} />
              Acesso ativo
            </label>
          )}
          <div className="row" style={{ justifyContent: "space-between" }}>
            <div>{dev && <button type="button" className="btn btn-danger" onClick={remove} disabled={a.busy}>Remover acesso</button>}</div>
            <button className="btn btn-primary" disabled={a.busy}>{dev ? "Salvar acesso aos equipamentos" : "Criar acesso aos equipamentos"}</button>
          </div>
          {a.view}
        </form>
      )}

      {dev && (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <span className="row"><strong style={{ fontSize: 14 }}>TOTP dos equipamentos</strong>
                <span className={"pill " + (dev.totp_configured ? "pill-ok" : "pill-warn")}>{dev.totp_configured ? "Configurado" : "Não configurado"}</span></span>
              <button type="button" className="btn" onClick={newTotp} disabled={b.busy}>{dev.totp_configured ? "Gerar novo TOTP" : "Gerar TOTP"}</button>
            </div>
            {otp && (
              <div className="row" style={{ alignItems: "flex-start", gap: 16, padding: 14, borderRadius: 10, background: "var(--sunk)" }}>
                <canvas ref={qr} className="qr" aria-label="QR Code do TOTP dos equipamentos" />
                <div style={{ display: "flex", flexDirection: "column", gap: 6, flex: "1 1 240px" }}>
                  <span>Entregue à pessoa para ler no app autenticador. Ele aparece no app como <strong>ONE GATE (equipamentos)</strong>.</span>
                  <span className="muted" style={{ fontSize: 12.5 }}>Segredo para digitar manualmente:</span>
                  <span className="mono" style={{ wordBreak: "break-all" }}>{otp.secret}</span>
                </div>
              </div>
            )}
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <strong style={{ fontSize: 14 }}>Clientes onde a credencial vale</strong>
            <div className="row" style={{ gap: 14 }}>
              {customers.map((c) => (
                <label key={c.id} className="row" style={{ gap: 8, cursor: "pointer" }}>
                  <input type="checkbox" checked={sel.includes(c.id)} style={{ width: 18, height: 18 }}
                    onChange={(e) => setSel(e.target.checked ? [...sel, c.id] : sel.filter((x) => x !== c.id))} />
                  <CustomerBadge code={c.code} name={c.name} color={c.color} />
                </label>
              ))}
              {customers.length === 0 && <span className="muted">Cadastre clientes primeiro.</span>}
            </div>
            <span className="muted" style={{ fontSize: 12.5 }}>A credencial é publicada para os Edges desses clientes (sincronização no dia 7). Os grupos de técnicos de cada cliente definem o que a pessoa pode fazer nos equipamentos.</span>
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button type="button" className="btn btn-primary" onClick={saveCustomers} disabled={b.busy}>Salvar clientes</button>
            </div>
          </div>
          {b.view}
        </>
      )}
    </Section>
  );
}
