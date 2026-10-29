import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError, formatWindow, type AAADevice, type AAAObject } from "../api";
import { useAuth } from "../auth";
import { Icon } from "../components/Icon";
import { ScopePicker, useCustomerInfo } from "../components/ScopePicker";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : "Erro inesperado.";
}

const mfaLabel: Record<AAADevice["mfa"], string> = { inherit: "Herdar do grupo/cliente", totp: "TOTP obrigatório", off: "Desligado" };
const vendors = ["Huawei", "Cisco", "MikroTik", "Juniper", "Datacom", "ZTE", "Parks", "Ubiquiti", "Intelbras", "Fiberhome", "Linux"];

export function AaaDevices() {
  const { can } = useAuth();
  const [cid, setCid] = useState<string | null>(null);
  const [list, setList] = useState<AAADevice[]>([]);
  const [groups, setGroups] = useState<AAAObject[]>([]);
  const [editing, setEditing] = useState<AAADevice | "new" | null>(null);
  const [secret, setSecret] = useState<{ name: string; secret: string } | null>(null);
  const [msg, setMsg] = useState("");
  const cust = useCustomerInfo(cid);

  const load = useCallback(async (c: string) => {
    const [d, o] = await Promise.all([
      api.get<AAADevice[]>(`/api/aaa/devices?customer_id=${c}`),
      api.get<AAAObject[]>(`/api/aaa/objects?customer_id=${c}`),
    ]);
    setList(d);
    setGroups(o.filter((x) => x.kind === "device_group"));
  }, []);
  useEffect(() => {
    if (!cid) return;
    setMsg("");
    load(cid).catch((e) => setMsg(errMsg(e)));
  }, [cid, load]);

  const gname = (id: string) => groups.find((g) => g.id === id)?.name ?? "?";
  const edit = !!cid && can("aaa.devices.edit", cid);

  return (
    <>
      <div className="page-head">
        <div style={{ maxWidth: 760 }}>
          <h1>Equipamentos</h1>
          <p>Equipamentos e servidores que autenticam no Edge do cliente (TACACS+). O Edge reconhece o equipamento pelo IP de origem e usa a chave compartilhada dele.</p>
        </div>
        <div className="row" style={{ alignItems: "flex-end" }}>
          <ScopePicker fn="aaa.devices.view" value={cid} onChange={setCid} />
          {edit && <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}><Icon name="plus" /> Novo equipamento</button>}
        </div>
      </div>
      {msg && <div className="alert alert-err" role="alert">{msg}</div>}
      <section className="card table-wrap">
        <table>
          <thead>
            <tr><th>Equipamento</th><th>Endereço</th><th>Grupos</th><th>MFA</th><th>Situação</th></tr>
          </thead>
          <tbody>
            {list.length === 0 && <tr><td colSpan={5} className="muted">Nenhum equipamento em {cust?.name ?? "este cliente"}.</td></tr>}
            {list.map((d) => (
              <tr key={d.id} className={edit ? "clickable" : undefined} onClick={() => edit && setEditing(d)} tabIndex={edit ? 0 : undefined}
                onKeyDown={(e) => { if (edit && e.key === "Enter") setEditing(d); }}>
                <td><strong>{d.name}</strong><div className="muted" style={{ fontSize: 12 }}>{[d.vendor, d.model].filter(Boolean).join(" ") || "—"}</div></td>
                <td className="mono">{d.address}</td>
                <td>{d.group_ids.length ? d.group_ids.map((g, i) => <span key={g} className={"pill " + (i === 0 ? "pill-info" : "")} style={{ marginRight: 4, border: i ? "1px solid var(--border)" : undefined }}>{gname(g)}</span>) : <span className="muted">—</span>}</td>
                <td>{d.mfa === "totp" ? <span className="pill pill-info">TOTP</span> : d.mfa === "off" ? <span className="pill pill-warn">Desligado</span> : <span className="muted">Herdado</span>}
                  {d.code_entry === "append" && <div className="muted" style={{ fontSize: 11.5 }}>código junto da senha</div>}</td>
                <td>{d.active ? <span className="pill pill-ok">Ativo</span> : <span className="pill pill-err">Inativo</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      {editing && cid && (
        <DeviceDialog cid={cid} dev={editing === "new" ? null : editing} groups={groups} canSecret={can("aaa.devices.secret", cid)} canMfaOff={can("aaa.mfa.disable", cid)}
          onClose={() => setEditing(null)}
          onSaved={async (s) => { setEditing(null); if (s) setSecret(s); await load(cid); }} />
      )}
      {secret && (
        <div className="overlay" role="dialog" aria-modal="true" aria-labelledby="sec-title">
          <div className="card dialog">
            <h2 id="sec-title">Chave compartilhada de {secret.name}</h2>
            <p className="muted" style={{ margin: 0 }}>Configure esta chave no equipamento (tacacs-server key). Ela <strong>não aparece de novo</strong>: se perder, rotacione.</p>
            <div className="row" style={{ gap: 8 }}>
              <code className="mono" style={{ flex: 1, padding: "12px 14px", borderRadius: 10, background: "var(--sunk)", fontSize: 15, letterSpacing: ".04em", wordBreak: "break-all" }}>{secret.secret}</code>
              <button type="button" className="btn" onClick={() => void navigator.clipboard?.writeText(secret.secret)}>Copiar</button>
            </div>
            <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" className="btn btn-primary" onClick={() => setSecret(null)}>Já configurei</button></div>
          </div>
        </div>
      )}
    </>
  );
}

function DeviceDialog({ cid, dev, groups, canSecret, canMfaOff, onClose, onSaved }: {
  cid: string; dev: AAADevice | null; groups: AAAObject[]; canSecret: boolean; canMfaOff: boolean;
  onClose: () => void; onSaved: (secret?: { name: string; secret: string }) => Promise<void>;
}) {
  const [d, setD] = useState({
    name: dev?.name ?? "", address: dev?.address ?? "", vendor: dev?.vendor ?? "", model: dev?.model ?? "",
    mfa: dev?.mfa ?? "inherit", code_entry: dev?.code_entry ?? "prompt", window: dev?.trust_window_seconds != null ? String(dev.trust_window_seconds) : "",
    group_ids: dev?.group_ids ?? [], active: dev?.active ?? true, secret: "",
  });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof typeof d>(k: K, v: (typeof d)[K]) => setD((x) => ({ ...x, [k]: v }));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    setBusy(true);
    const body: Record<string, unknown> = {
      name: d.name, address: d.address, vendor: d.vendor, model: d.model, mfa: d.mfa, code_entry: d.code_entry, group_ids: d.group_ids, active: d.active,
      ...(d.window === "" ? { clear_trust_window: true } : { trust_window_seconds: Number(d.window) }),
    };
    try {
      if (dev) {
        await api.patch(`/api/aaa/devices/${dev.id}`, body);
        await onSaved();
      } else {
        const r = await api.post<{ id: string; secret: string }>("/api/aaa/devices", { ...body, customer_id: cid, ...(d.secret ? { secret: d.secret } : {}) });
        await onSaved(d.secret ? undefined : { name: d.name, secret: r.secret });
      }
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  };
  const rotate = async () => {
    if (!dev) return;
    setBusy(true);
    try {
      const r = await api.post<{ secret: string }>(`/api/aaa/devices/${dev.id}/rotate-secret`);
      await onSaved({ name: dev.name, secret: r.secret });
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!dev) return;
    setBusy(true);
    try {
      await api.del(`/api/aaa/devices/${dev.id}`);
      await onSaved();
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  };
  const toggleGroup = (id: string) => set("group_ids", d.group_ids.includes(id) ? d.group_ids.filter((g) => g !== id) : [...d.group_ids, id]);

  return (
    <div className="overlay" role="dialog" aria-modal="true" aria-labelledby="dev-title">
      <form className="card dialog" onSubmit={submit} style={{ maxWidth: 720 }}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2 id="dev-title">{dev ? `Equipamento ${dev.name}` : "Novo equipamento"}</h2>
          <button type="button" className="btn btn-icon" onClick={onClose} aria-label="Fechar"><Icon name="x" /></button>
        </div>
        <div className="form-grid">
          <label className="field"><span>Nome</span><input className="input" value={d.name} onChange={(e) => set("name", e.target.value)} required placeholder="bng-01" /></label>
          <label className="field"><span>IP de origem (NAS)</span><input className="input mono" value={d.address} onChange={(e) => set("address", e.target.value)} required placeholder="10.0.0.1 ou 10.0.8.0/24" />
            <small>Uma faixa cobre vários equipamentos com a mesma chave.</small></label>
          <label className="field"><span>Fabricante</span>
            <input className="input" list="vendors" value={d.vendor} onChange={(e) => set("vendor", e.target.value)} placeholder="Huawei" />
            <datalist id="vendors">{vendors.map((v) => <option key={v} value={v} />)}</datalist>
            <small>Regras podem usar “Fabricante X” em Onde.</small>
          </label>
          <label className="field"><span>Modelo</span><input className="input" value={d.model} onChange={(e) => set("model", e.target.value)} placeholder="NE8000" /></label>
        </div>
        <div className="field">
          <span>Grupos</span>
          <div className="row" style={{ gap: 6 }}>
            {groups.length === 0 && <span className="muted" style={{ fontSize: 13 }}>Nenhum grupo de equipamentos (crie em Objetos AAA).</span>}
            {groups.map((g) => {
              const i = d.group_ids.indexOf(g.id);
              return (
                <button key={g.id} type="button" aria-pressed={i >= 0} onClick={() => toggleGroup(g.id)}
                  style={{ minHeight: 34, padding: "0 12px", borderRadius: 999, border: "1px solid var(--border)", font: "inherit", fontSize: 13, fontWeight: 600, cursor: "pointer", background: i >= 0 ? "var(--accent-soft)" : "transparent", color: i >= 0 ? "var(--accent-text)" : "var(--muted)" }}>
                  {i === 0 ? "★ " : ""}{g.name}{g.customer_id ? "" : " · global"}
                </button>
              );
            })}
          </div>
          <small>O primeiro escolhido (★) é o grupo principal: dele vem a herança de MFA.</small>
        </div>
        <div className="form-grid">
          <label className="field"><span>MFA</span>
            <select className="input" value={d.mfa} onChange={(e) => set("mfa", e.target.value as AAADevice["mfa"])}>
              {Object.entries(mfaLabel).map(([k, v]) => <option key={k} value={k} disabled={k === "off" && !canMfaOff && dev?.mfa !== "off"}>{v}</option>)}
            </select>
          </label>
          <label className="field"><span>Como o técnico informa o código</span>
            <select className="input" value={d.code_entry} onChange={(e) => set("code_entry", e.target.value as AAADevice["code_entry"])}>
              <option value="prompt">Segundo prompt (“Código MFA:”)</option>
              <option value="append">Junto da senha (senha + 6 dígitos)</option>
            </select>
            <small>Use “junto da senha” em equipamentos que só fazem PAP.</small>
          </label>
          <label className="field"><span>Janela de confiança</span>
            <select className="input" value={d.window} onChange={(e) => set("window", e.target.value)}>
              <option value="">Herdar do grupo/cliente</option>
              {[0, 900, 1800, 3600, 14400, 28800].map((w) => <option key={w} value={w}>{formatWindow(w)}</option>)}
            </select>
          </label>
        </div>
        {!dev && (
          <label className="field"><span>Chave compartilhada (opcional)</span>
            <input className="input mono" value={d.secret} onChange={(e) => set("secret", e.target.value)} minLength={16} placeholder="Deixe vazio para gerar uma chave forte" autoComplete="off" />
            <small>Só informe se o equipamento já tem uma chave configurada (mínimo 16 caracteres).</small>
          </label>
        )}
        {dev && (
          <label className="row" style={{ cursor: "pointer" }}>
            <input type="checkbox" checked={d.active} onChange={(e) => set("active", e.target.checked)} style={{ width: 18, height: 18 }} />
            Equipamento ativo (inativo sai da política e não autentica)
          </label>
        )}
        {err && <div className="alert alert-err" role="alert">{err}</div>}
        <div className="row" style={{ justifyContent: "space-between" }}>
          <div className="row">
            {dev && <button type="button" className="btn btn-danger" disabled={busy} onClick={() => void remove()}>Apagar</button>}
            {dev && canSecret && <button type="button" className="btn" disabled={busy} onClick={() => void rotate()}>Rotacionar chave</button>}
          </div>
          <div className="row">
            <button type="button" className="btn" onClick={onClose}>Cancelar</button>
            <button className="btn btn-primary" disabled={busy}>{dev ? "Salvar" : "Cadastrar"}</button>
          </div>
        </div>
      </form>
    </div>
  );
}
