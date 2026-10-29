import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, ApiError, formatDate, roleLabels, type Customer, type Role, type StaffUser } from "../api";
import { useAuth } from "../auth";
import { CustomerBadge, CodeBox } from "../components/CustomerBadge";
import { Icon } from "../components/Icon";

export function Staff() {
  const { me } = useAuth();
  const [list, setList] = useState<StaffUser[]>([]);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<StaffUser | null>(null);

  const load = async () => {
    try {
      const [s, c] = await Promise.all([api.get<StaffUser[]>("/api/staff"), api.get<Customer[]>("/api/customers")]);
      setList(s);
      setCustomers(c);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Erro ao carregar.");
    }
  };
  useEffect(() => {
    void load();
  }, []);

  const byId = useMemo(() => Object.fromEntries(customers.map((c) => [c.id, c])), [customers]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Equipe e permissões</h1>
          <p>O usuário de cada pessoa é o mesmo que ela usa para entrar nos equipamentos dos clientes.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setCreating(true)}><Icon name="plus" /> Novo membro</button>
      </div>
      {error && <div className="alert alert-err">{error}</div>}

      <section className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Nome</th><th>Usuário</th><th>Acesso</th><th>Clientes</th><th>TOTP</th><th>Último login</th><th>Situação</th></tr>
            </thead>
            <tbody>
              {list.map((u) => (
                <tr key={u.id} className="clickable" onClick={() => setEditing(u)}>
                  <td>
                    <button type="button" style={{ all: "unset", cursor: "pointer", display: "flex", flexDirection: "column" }} onClick={() => setEditing(u)}>
                      <strong>{u.name}</strong><span className="muted" style={{ fontSize: 12 }}>{u.email}</span>
                    </button>
                  </td>
                  <td className="mono">{u.username}</td>
                  <td>{u.is_admin ? <span className="pill pill-info">Administrador</span> : <span className="muted">Equipe</span>}</td>
                  <td>
                    {u.is_admin ? <span className="muted">Todos</span> : (
                      <span className="row" style={{ gap: 4 }}>
                        {u.roles.length === 0 && <span className="muted">Nenhum</span>}
                        {u.roles.map((r) => byId[r.customer_id] && (
                          <CodeBox key={r.customer_id} code={byId[r.customer_id].code} color={byId[r.customer_id].color} title={`${byId[r.customer_id].name}: ${roleLabels[r.role]}`} />
                        ))}
                      </span>
                    )}
                  </td>
                  <td>{u.totp_enabled ? <span className="pill pill-ok">Ativo</span> : <span className="pill pill-warn">Pendente</span>}</td>
                  <td className="muted">{formatDate(u.last_login_at)}</td>
                  <td>{u.active ? <span className="pill pill-ok">Ativo</span> : <span className="pill pill-err">Desativado</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {creating && <CreateDialog onClose={() => setCreating(false)} onSaved={() => { setCreating(false); void load(); }} />}
      {editing && (
        <EditDialog user={editing} self={editing.id === me?.id} customers={customers}
          onClose={() => setEditing(null)} onSaved={() => { setEditing(null); void load(); }} />
      )}
    </>
  );
}

function Dialog({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="overlay" role="dialog" aria-modal="true" aria-label={title} onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="card dialog">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2 style={{ fontSize: 18 }}>{title}</h2>
          <button type="button" className="btn btn-icon" onClick={onClose} aria-label="Fechar"><Icon name="x" /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

function CreateDialog({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState({ name: "", email: "", username: "", password: "", is_admin: false });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.post("/api/staff", f);
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Erro ao salvar.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog title="Novo membro da equipe" onClose={onClose}>
      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <div className="form-grid">
          <label className="field"><span>Nome</span><input className="input" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
          <label className="field"><span>E-mail</span><input className="input" type="email" required value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
          <label className="field">
            <span>Usuário</span>
            <input className="input mono" required value={f.username} onChange={(e) => setF({ ...f, username: e.target.value.toLowerCase() })} />
            <small>Usado também nos equipamentos (ex.: joao.silva).</small>
          </label>
          <label className="field">
            <span>Senha inicial</span>
            <input className="input" type="password" autoComplete="new-password" minLength={12} required value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
            <small>Mínimo 12 caracteres. O TOTP é cadastrado no primeiro login.</small>
          </label>
        </div>
        <label className="row" style={{ cursor: "pointer" }}>
          <input type="checkbox" checked={f.is_admin} onChange={(e) => setF({ ...f, is_admin: e.target.checked })} style={{ width: 18, height: 18 }} />
          Administrador da plataforma (acesso a todos os clientes)
        </label>
        {error && <div className="alert alert-err" role="alert">{error}</div>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn" onClick={onClose}>Cancelar</button>
          <button className="btn btn-primary" disabled={busy}>Cadastrar</button>
        </div>
      </form>
    </Dialog>
  );
}

function EditDialog({ user, self, customers, onClose, onSaved }: { user: StaffUser; self: boolean; customers: Customer[]; onClose: () => void; onSaved: () => void }) {
  const [isAdmin, setIsAdmin] = useState(user.is_admin);
  const [active, setActive] = useState(user.active);
  const [roles, setRoles] = useState<Record<string, Role | "">>(Object.fromEntries(user.roles.map((r) => [r.customer_id, r.role])));
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    setError("");
    try {
      if (isAdmin !== user.is_admin || active !== user.active) {
        await api.patch(`/api/staff/${user.id}`, { is_admin: isAdmin, active });
      }
      const list = Object.entries(roles).filter(([, r]) => r).map(([customer_id, role]) => ({ customer_id, role }));
      await api.put(`/api/staff/${user.id}/roles`, list);
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Erro ao salvar.");
    } finally {
      setBusy(false);
    }
  };

  const resetTotp = async () => {
    if (!confirm(`Redefinir o TOTP de ${user.name}? As sessões dele serão encerradas e ele cadastrará o app de novo no próximo login.`)) return;
    try {
      await api.post(`/api/staff/${user.id}/reset-totp`);
      setInfo("TOTP redefinido. No próximo login a pessoa cadastra o app autenticador de novo.");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Erro ao redefinir.");
    }
  };

  return (
    <Dialog title={user.name} onClose={onClose}>
      <span className="muted">{user.email} · <span className="mono">{user.username}</span></span>
      <label className="row" style={{ cursor: self ? "not-allowed" : "pointer" }}>
        <input type="checkbox" disabled={self} checked={isAdmin} onChange={(e) => setIsAdmin(e.target.checked)} style={{ width: 18, height: 18 }} />
        Administrador da plataforma
      </label>
      <label className="row" style={{ cursor: self ? "not-allowed" : "pointer" }}>
        <input type="checkbox" disabled={self} checked={active} onChange={(e) => setActive(e.target.checked)} style={{ width: 18, height: 18 }} />
        Acesso ativo
      </label>

      {!isAdmin && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <strong>Acesso por cliente</strong>
          {customers.length === 0 && <span className="muted">Cadastre clientes primeiro.</span>}
          {customers.map((c) => (
            <div key={c.id} className="row" style={{ justifyContent: "space-between" }}>
              <CustomerBadge code={c.code} name={c.name} color={c.color} />
              <select className="input" style={{ width: 230 }} value={roles[c.id] ?? ""} aria-label={`Papel em ${c.name}`}
                onChange={(e) => setRoles({ ...roles, [c.id]: e.target.value as Role | "" })}>
                <option value="">Sem acesso</option>
                {(Object.keys(roleLabels) as Role[]).map((r) => <option key={r} value={r}>{roleLabels[r]}</option>)}
              </select>
            </div>
          ))}
        </div>
      )}

      {info && <div className="alert alert-ok">{info}</div>}
      {error && <div className="alert alert-err" role="alert">{error}</div>}
      <div className="row" style={{ justifyContent: "space-between" }}>
        <button type="button" className="btn btn-danger" onClick={() => void resetTotp()} disabled={!user.totp_enabled}>Redefinir TOTP</button>
        <div className="row">
          <button type="button" className="btn" onClick={onClose}>Cancelar</button>
          <button type="button" className="btn btn-primary" onClick={() => void save()} disabled={busy}>Salvar</button>
        </div>
      </div>
    </Dialog>
  );
}
