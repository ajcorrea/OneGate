import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError, formatWindow, segments, type Customer } from "../api";
import { useAuth } from "../auth";
import { CustomerBadge } from "../components/CustomerBadge";
import { Icon } from "../components/Icon";

const windows = [0, 1800, 3600, 14400, 28800];
const palette = ["#2563EB", "#B45309", "#047857", "#BE185D", "#6D28D9", "#0E7490", "#B91C1C", "#4D7C0F"];

type Draft = Omit<Customer, "id" | "created_at" | "updated_at">;

const empty: Draft = { code: "", name: "", segment: "provedor", color: palette[0], mfa: "totp", trust_window_seconds: 3600, active: true };

export function Customers() {
  const { me } = useAuth();
  const [list, setList] = useState<Customer[] | null>(null);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState<{ id?: string; draft: Draft } | null>(null);

  const load = () =>
    api.get<Customer[]>("/api/customers").then(setList).catch((e) => setError(e instanceof ApiError ? e.message : "Erro ao carregar."));
  useEffect(() => {
    void load();
  }, []);

  const open = (c?: Customer) => {
    if (!me?.is_admin) return;
    if (c) {
      const { id, created_at: _c, updated_at: _u, ...draft } = c;
      setEditing({ id, draft });
    } else {
      setEditing({ draft: { ...empty, color: palette[(list?.length ?? 0) % palette.length] } });
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Clientes</h1>
          <p>Provedores e empresas de qualquer segmento. O código e a cor identificam o cliente em todas as telas.</p>
        </div>
        {me?.is_admin && (
          <button className="btn btn-primary" onClick={() => open()}>
            <Icon name="plus" /> Novo cliente
          </button>
        )}
      </div>
      {error && <div className="alert alert-err">{error}</div>}

      <section className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Cliente</th>
                <th>Segmento</th>
                <th>MFA padrão</th>
                <th>Janela de confiança</th>
                <th>Situação</th>
              </tr>
            </thead>
            <tbody>
              {list?.map((c) => (
                <tr key={c.id} className={me?.is_admin ? "clickable" : undefined} onClick={() => open(c)}>
                  <td>
                    {me?.is_admin ? (
                      <button type="button" onClick={() => open(c)} style={{ all: "unset", cursor: "pointer" }} aria-label={`Editar ${c.name}`}>
                        <CustomerBadge code={c.code} name={c.name} color={c.color} />
                      </button>
                    ) : (
                      <CustomerBadge code={c.code} name={c.name} color={c.color} />
                    )}
                  </td>
                  <td className="muted">{segments[c.segment] ?? c.segment}</td>
                  <td>{c.mfa === "totp" ? <span className="pill pill-info">TOTP</span> : <span className="pill pill-warn">Desligado</span>}</td>
                  <td className="muted">{c.mfa === "totp" ? formatWindow(c.trust_window_seconds) : "—"}</td>
                  <td>{c.active ? <span className="pill pill-ok">Ativo</span> : <span className="pill pill-err">Inativo</span>}</td>
                </tr>
              ))}
              {list?.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">Nenhum cliente {me?.is_admin ? "cadastrado ainda." : "liberado para você."}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {editing && (
        <CustomerDialog
          id={editing.id}
          initial={editing.draft}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void load();
          }}
        />
      )}
    </>
  );
}

function CustomerDialog({ id, initial, onClose, onSaved }: { id?: string; initial: Draft; onClose: () => void; onSaved: () => void }) {
  const [d, setD] = useState<Draft>(initial);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((p) => ({ ...p, [k]: v }));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (id) await api.patch(`/api/customers/${id}`, d);
      else await api.post("/api/customers", d);
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Erro ao salvar.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="overlay" role="dialog" aria-modal="true" aria-labelledby="cust-title" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <form className="card dialog" onSubmit={submit}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2 id="cust-title" style={{ fontSize: 18 }}>{id ? "Editar cliente" : "Novo cliente"}</h2>
          <button type="button" className="btn btn-icon" onClick={onClose} aria-label="Fechar"><Icon name="x" /></button>
        </div>

        <div className="row">
          <span className="muted" style={{ fontSize: 13 }}>Prévia:</span>
          <CustomerBadge code={d.code.toUpperCase() || "???"} name={d.name || "Nome do cliente"} color={d.color} />
        </div>

        <div className="form-grid">
          <label className="field">
            <span>Código</span>
            <input className="input mono" maxLength={3} required value={d.code} onChange={(e) => set("code", e.target.value.toUpperCase())} />
            <small>3 letras ou números, único.</small>
          </label>
          <label className="field">
            <span>Nome</span>
            <input className="input" required value={d.name} onChange={(e) => set("name", e.target.value)} />
          </label>
          <label className="field">
            <span>Segmento</span>
            <select className="input" value={d.segment} onChange={(e) => set("segment", e.target.value)}>
              {Object.entries(segments).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <div className="field">
            <span>Cor do badge</span>
            <div className="row" style={{ gap: 6 }}>
              {palette.map((p) => (
                <button key={p} type="button" aria-label={`Cor ${p}`} aria-pressed={d.color === p} onClick={() => set("color", p)}
                  style={{ width: 28, height: 28, borderRadius: 6, background: p, cursor: "pointer", border: d.color === p ? "3px solid var(--text)" : "1px solid var(--border)" }} />
              ))}
              <input type="color" aria-label="Outra cor" value={d.color} onChange={(e) => set("color", e.target.value.toUpperCase())} style={{ width: 36, height: 30, border: 0, background: "none" }} />
            </div>
          </div>
          <label className="field">
            <span>MFA padrão dos equipamentos</span>
            <select className="input" value={d.mfa} onChange={(e) => set("mfa", e.target.value as Draft["mfa"])}>
              <option value="totp">TOTP obrigatório</option>
              <option value="off">Desligado</option>
            </select>
            <small>Grupos e equipamentos podem sobrescrever.</small>
          </label>
          <label className="field">
            <span>Janela de confiança padrão</span>
            <select className="input" value={d.trust_window_seconds} onChange={(e) => set("trust_window_seconds", Number(e.target.value))}>
              {windows.map((w) => <option key={w} value={w}>{formatWindow(w)}</option>)}
            </select>
          </label>
        </div>
        {id && (
          <label className="row" style={{ cursor: "pointer" }}>
            <input type="checkbox" checked={d.active} onChange={(e) => set("active", e.target.checked)} style={{ width: 18, height: 18 }} />
            Cliente ativo
          </label>
        )}
        {error && <div className="alert alert-err" role="alert">{error}</div>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn" onClick={onClose}>Cancelar</button>
          <button className="btn btn-primary" disabled={busy}>{id ? "Salvar alterações" : "Cadastrar cliente"}</button>
        </div>
      </form>
    </div>
  );
}
