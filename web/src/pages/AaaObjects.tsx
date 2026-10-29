import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError, formatWindow, objKinds, type AAAObject, type ObjKind, type Person } from "../api";
import { useAuth } from "../auth";
import { Icon } from "../components/Icon";
import { ScopePicker, useCustomerInfo } from "../components/ScopePicker";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : "Erro inesperado.";
}

const days = ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"];
const windows = [0, 900, 1800, 3600, 14400, 28800];
type Win = { days: number[]; start: string; end: string };

function summary(o: AAAObject): string {
  const d = o.data ?? {};
  switch (o.kind) {
    case "user_group":
      return `${o.members?.length ?? 0} técnicos`;
    case "device_group":
      return `MFA ${d.mfa === "totp" ? "TOTP" : d.mfa === "off" ? "desligado" : "herdado"}` + (d.trust_window_seconds != null ? ` · janela ${formatWindow(d.trust_window_seconds)}` : "");
    case "network":
      return (d.cidrs ?? []).join(", ");
    case "profile":
      return `priv ${d.priv_level ?? 0} · ` + (d.allow?.length ? `${d.allow.length} permitidos` : d.deny?.length ? `tudo, exceto ${d.deny.length}` : "todos os comandos");
    case "schedule":
      return (d.windows ?? []).map((w: Win) => `${w.days.map((x) => days[x - 1]).join(",")} ${w.start}–${w.end}`).join(" · ");
  }
}

export function AaaObjects() {
  const { can } = useAuth();
  const [scope, setScope] = useState<string | null>(null);
  const [kind, setKind] = useState<ObjKind>("user_group");
  const [objs, setObjs] = useState<AAAObject[]>([]);
  const [people, setPeople] = useState<Person[]>([]);
  const [sel, setSel] = useState<AAAObject | "new" | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const cust = useCustomerInfo(scope);

  const load = useCallback(async (sc: string) => {
    const [o, p] = await Promise.all([
      api.get<AAAObject[]>(`/api/aaa/objects${sc ? `?customer_id=${sc}` : ""}`),
      api.get<Person[]>("/api/people").catch(() => [] as Person[]),
    ]);
    setObjs(o);
    setPeople(p);
  }, []);
  useEffect(() => {
    if (scope === null) return;
    setSel(null);
    setMsg(null);
    load(scope).catch((e) => setMsg({ ok: false, text: errMsg(e) }));
  }, [scope, load]);

  const list = objs.filter((o) => o.kind === kind);
  const canEdit = (o: AAAObject | null) => can("aaa.rules.edit", (o ? o.customer_id : scope) || undefined);
  const selected = sel === "new" ? null : sel ? objs.find((o) => o.id === sel.id) ?? null : null;

  return (
    <>
      <div className="page-head">
        <div style={{ maxWidth: 780 }}>
          <h1>Objetos AAA</h1>
          <p>Os blocos que as regras usam. Objetos <strong>globais</strong> valem em todos os clientes; os do cliente, só nele. Mudanças nos objetos valem na próxima política enviada aos Edges, sem publicar as regras de novo.</p>
        </div>
        <ScopePicker fn="aaa.rules.view" value={scope} onChange={setScope} allowGlobal label="Escopo" />
      </div>
      {msg && <div className={"alert " + (msg.ok ? "alert-ok" : "alert-err")} role={msg.ok ? "status" : "alert"}>{msg.text}</div>}
      <div role="tablist" style={{ display: "flex", flexWrap: "wrap", borderBottom: "1px solid var(--border)" }}>
        {(Object.keys(objKinds) as ObjKind[]).map((k) => (
          <button key={k} type="button" role="tab" aria-selected={kind === k} onClick={() => { setKind(k); setSel(null); }}
            style={{ minHeight: 44, padding: "0 4px", marginRight: 22, border: 0, borderBottom: `2px solid ${kind === k ? "var(--accent)" : "transparent"}`, background: "transparent", font: "inherit", cursor: "pointer", fontWeight: kind === k ? 600 : 500, color: kind === k ? "var(--text)" : "var(--muted)" }}>
            {objKinds[k].plural} <span className="muted" style={{ fontWeight: 500 }}>· {objs.filter((o) => o.kind === k).length}</span>
          </button>
        ))}
      </div>
      <div className="row" style={{ alignItems: "flex-start", gap: 16 }}>
        <section className="card" style={{ flex: "1 1 300px", padding: 10, display: "flex", flexDirection: "column", gap: 4 }}>
          {list.length === 0 && <p className="muted" style={{ margin: 8 }}>Nenhum objeto deste tipo.</p>}
          {list.map((o) => (
            <button key={o.id} type="button" onClick={() => setSel(o)}
              style={{ display: "flex", flexDirection: "column", gap: 4, padding: "10px 12px", borderRadius: 10, font: "inherit", color: "var(--text)", cursor: "pointer", textAlign: "left", border: `1px solid ${selected?.id === o.id ? "var(--accent)" : "transparent"}`, background: selected?.id === o.id ? "var(--accent-soft)" : "transparent" }}>
              <span className="row" style={{ justifyContent: "space-between", width: "100%" }}>
                <strong>{o.name}</strong>
                <span className={"pill " + (o.customer_id ? "pill-ok" : "pill-info")}>{o.customer_id ? "Cliente" : "Global"}</span>
              </span>
              <span className="muted" style={{ fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "100%" }}>{summary(o)}</span>
            </button>
          ))}
          {canEdit(null) && (
            <button type="button" className="btn" style={{ borderStyle: "dashed", color: "var(--accent-text)" }} onClick={() => setSel("new")}>
              <Icon name="plus" /> Novo: {objKinds[kind].label.toLowerCase()} {scope ? `de ${cust?.code ?? "cliente"}` : "global"}
            </button>
          )}
        </section>
        <section className="card card-pad" style={{ flex: "2 1 520px", minWidth: 0 }}>
          {sel === null ? (
            <p className="muted" style={{ margin: 0 }}>Escolha um objeto à esquerda ou crie um novo.</p>
          ) : (
            <ObjectEditor key={(selected?.id ?? "novo") + kind} kind={kind} obj={selected} scope={scope ?? ""} people={people}
              editable={canEdit(selected)} canMembers={can("aaa.users.manage", (selected?.customer_id ?? scope) || undefined)}
              onSaved={async (text, id) => { await load(scope!); setMsg({ ok: true, text }); setSel(id ? ({ id } as AAAObject) : null); }}
              onError={(text) => setMsg({ ok: false, text })} />
          )}
        </section>
      </div>
    </>
  );
}

function ObjectEditor({ kind, obj, scope, people, editable, canMembers, onSaved, onError }: {
  kind: ObjKind; obj: AAAObject | null; scope: string; people: Person[]; editable: boolean; canMembers: boolean;
  onSaved: (msg: string, id?: string) => Promise<void>; onError: (msg: string) => void;
}) {
  const d = obj?.data ?? {};
  const [name, setName] = useState(obj?.name ?? "");
  const [desc, setDesc] = useState(obj?.description ?? "");
  const [mfa, setMfa] = useState<string>(d.mfa ?? "inherit");
  const [win, setWin] = useState<string>(d.trust_window_seconds != null ? String(d.trust_window_seconds) : "");
  const [cidrs, setCidrs] = useState<string>((d.cidrs ?? []).join("\n"));
  const [priv, setPriv] = useState<number>(d.priv_level ?? 15);
  const [def, setDef] = useState<string>(d.default ?? "");
  const [allow, setAllow] = useState<string>((d.allow ?? []).join("\n"));
  const [deny, setDeny] = useState<string>((d.deny ?? []).join("\n"));
  const [wins, setWins] = useState<Win[]>(d.windows ?? [{ days: [1, 2, 3, 4, 5], start: "08:00", end: "18:00" }]);
  const [members, setMembers] = useState<string[]>(obj?.members ?? []);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const lines = (s: string) => s.split("\n").map((x) => x.trim()).filter(Boolean);

  const data = () => {
    switch (kind) {
      case "user_group":
        return {};
      case "device_group":
        return { mfa, ...(win !== "" ? { trust_window_seconds: Number(win) } : {}) };
      case "network":
        return { cidrs: lines(cidrs) };
      case "profile":
        return { priv_level: priv, ...(def ? { default: def } : {}), allow: lines(allow), deny: lines(deny) };
      case "schedule":
        return { windows: wins };
    }
  };

  const save = async () => {
    setBusy(true);
    try {
      if (obj) {
        await api.patch(`/api/aaa/objects/${obj.id}`, { name, description: desc, data: data() });
        await onSaved(`${objKinds[kind].label} salvo.`, obj.id);
      } else {
        const r = await api.post<{ id: string }>("/api/aaa/objects", { customer_id: scope || null, kind, name, description: desc, data: data() });
        await onSaved(`${objKinds[kind].label} criado.`, r.id);
      }
    } catch (e) {
      onError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!obj) return;
    setBusy(true);
    try {
      await api.del(`/api/aaa/objects/${obj.id}`);
      await onSaved(`${objKinds[kind].label} apagado.`);
    } catch (e) {
      onError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };
  const saveMembers = async () => {
    if (!obj) return;
    setBusy(true);
    try {
      await api.put(`/api/aaa/objects/${obj.id}/members`, { person_ids: members });
      await onSaved("Membros do grupo salvos.", obj.id);
    } catch (e) {
      onError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  // Técnicos do mesmo domínio do grupo, com acesso aos equipamentos.
  const groupScope = obj ? obj.customer_id ?? "" : scope;
  const techs = useMemo(() => people.filter((p) => (p.customer_id ?? "") === groupScope && p.device), [people, groupScope]);
  const byId = useMemo(() => new Map(people.map((p) => [p.id, p])), [people]);
  const found = q.trim().length >= 3
    ? techs.filter((p) => !members.includes(p.id) && (p.name + " " + p.device!.username).toLowerCase().normalize("NFD").replace(/\p{Mn}/gu, "").includes(q.toLowerCase().normalize("NFD").replace(/\p{Mn}/gu, ""))).slice(0, 8)
    : [];
  const dis = !editable;

  return (
    <form style={{ display: "flex", flexDirection: "column", gap: 16 }} onSubmit={(e) => { e.preventDefault(); void save(); }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>{obj ? obj.name : `Novo: ${objKinds[kind].label.toLowerCase()}`}</h2>
        <span className={"pill " + ((obj ? obj.customer_id : scope) ? "pill-ok" : "pill-info")}>{(obj ? obj.customer_id : scope) ? "Do cliente" : "Global"}</span>
      </div>
      <div className="form-grid">
        <label className="field"><span>Nome</span><input className="input" value={name} onChange={(e) => setName(e.target.value)} disabled={dis} required minLength={2} maxLength={60} /></label>
        <label className="field"><span>Descrição</span><input className="input" value={desc} onChange={(e) => setDesc(e.target.value)} disabled={dis} /></label>
      </div>

      {kind === "device_group" && (
        <div className="form-grid">
          <label className="field"><span>MFA do grupo</span>
            <select className="input" value={mfa} onChange={(e) => setMfa(e.target.value)} disabled={dis}>
              <option value="inherit">Herdar do cliente</option><option value="totp">TOTP obrigatório</option><option value="off">Desligado</option>
            </select>
            <small>O equipamento pode sobrescrever. A regra decide por último (TOTP, segue o equipamento ou sem MFA).</small>
          </label>
          <label className="field"><span>Janela de confiança</span>
            <select className="input" value={win} onChange={(e) => setWin(e.target.value)} disabled={dis}>
              <option value="">Herdar do cliente</option>
              {windows.map((w) => <option key={w} value={w}>{formatWindow(w)}</option>)}
            </select>
          </label>
        </div>
      )}
      {kind === "network" && (
        <label className="field"><span>Faixas de IP (uma por linha)</span>
          <textarea className="input mono" rows={5} style={{ paddingTop: 10 }} value={cidrs} onChange={(e) => setCidrs(e.target.value)} disabled={dis} placeholder={"10.20.0.0/16\n172.16.50.7"} />
          <small>IP solto vale como /32. IPv6 também é aceito.</small>
        </label>
      )}
      {kind === "profile" && (
        <>
          <div className="form-grid">
            <label className="field"><span>Nível de privilégio (priv-lvl)</span><input className="input" type="number" min={0} max={15} value={priv} onChange={(e) => setPriv(Number(e.target.value))} disabled={dis} /></label>
            <label className="field"><span>Comando fora das listas</span>
              <select className="input" value={def} onChange={(e) => setDef(e.target.value)} disabled={dis}>
                <option value="">Automático (nega se houver lista de permitidos)</option><option value="allow">Permitir</option><option value="deny">Negar</option>
              </select>
            </label>
          </div>
          <div className="form-grid">
            <label className="field"><span>Permitidos (um padrão por linha)</span>
              <textarea className="input mono" rows={7} style={{ paddingTop: 10 }} value={allow} onChange={(e) => setAllow(e.target.value)} disabled={dis} placeholder={"display *\nshow *\nping *"} />
            </label>
            <label className="field"><span>Negados (avaliados antes)</span>
              <textarea className="input mono" rows={7} style={{ paddingTop: 10 }} value={deny} onChange={(e) => setDeny(e.target.value)} disabled={dis} placeholder={"display current-configuration *\nbgp *"} />
            </label>
          </div>
          <small className="muted">“*” é curinga e maiúsculas não importam. Um padrão terminado em “ *” também aceita o comando sem argumentos (“display *” aceita “display”).</small>
        </>
      )}
      {kind === "schedule" && (
        <div className="field">
          <span>Janelas</span>
          {wins.map((w, i) => (
            <div key={i} className="row" style={{ gap: 8 }}>
              <div role="group" aria-label={`Dias da janela ${i + 1}`} className="row" style={{ gap: 4 }}>
                {days.map((dn, j) => {
                  const on = w.days.includes(j + 1);
                  return (
                    <button key={dn} type="button" aria-pressed={on} disabled={dis}
                      onClick={() => setWins(wins.map((x, k) => (k === i ? { ...x, days: on ? x.days.filter((y) => y !== j + 1) : [...x.days, j + 1].sort() } : x)))}
                      style={{ minHeight: 34, minWidth: 40, borderRadius: 8, border: "1px solid var(--border)", font: "inherit", fontSize: 12.5, fontWeight: 600, cursor: "pointer", background: on ? "var(--accent-soft)" : "transparent", color: on ? "var(--accent-text)" : "var(--muted)" }}>{dn}</button>
                  );
                })}
              </div>
              <input className="input" type="time" aria-label="Início" style={{ width: 120, minHeight: 36 }} value={w.start} disabled={dis} onChange={(e) => setWins(wins.map((x, k) => (k === i ? { ...x, start: e.target.value } : x)))} />
              <span className="muted">até</span>
              <input className="input" type="time" aria-label="Fim" style={{ width: 120, minHeight: 36 }} value={w.end} disabled={dis} onChange={(e) => setWins(wins.map((x, k) => (k === i ? { ...x, end: e.target.value } : x)))} />
              {!dis && wins.length > 1 && <button type="button" className="btn btn-icon btn-danger" style={{ minHeight: 34, width: 34 }} aria-label="Remover janela" onClick={() => setWins(wins.filter((_, k) => k !== i))}><Icon name="x" size={16} /></button>}
            </div>
          ))}
          {!dis && <button type="button" className="btn" style={{ alignSelf: "flex-start" }} onClick={() => setWins([...wins, { days: [6, 7], start: "00:00", end: "24:00" }])}><Icon name="plus" /> Janela</button>}
          <small>Fim menor que o início atravessa a meia-noite (ex.: plantão 18:00–08:00; o dia é o do início). Os horários seguem o fuso do cliente.</small>
        </div>
      )}

      {editable && (
        <div className="row" style={{ justifyContent: "space-between" }}>
          {obj ? <button type="button" className="btn btn-danger" disabled={busy} onClick={() => void remove()}>Apagar</button> : <span />}
          <button className="btn btn-primary" disabled={busy}>{obj ? "Salvar" : "Criar"}</button>
        </div>
      )}

      {kind === "user_group" && obj && (
        <div style={{ borderTop: "1px solid var(--border)", paddingTop: 16, display: "flex", flexDirection: "column", gap: 10 }}>
          <h2>Técnicos no grupo <span className="muted" style={{ fontWeight: 500 }}>· {members.length}</span></h2>
          <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>Só pessoas do mesmo domínio e com acesso aos equipamentos (cadastre em Pessoas e acessos).</p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {members.length === 0 && <span className="muted" style={{ fontSize: 13 }}>Nenhum técnico.</span>}
            {members.map((id) => {
              const p = byId.get(id);
              return (
                <span key={id} className="pill pill-info" style={{ gap: 6, paddingRight: canMembers ? 4 : 9 }}>
                  {p?.device?.username ?? p?.name ?? id}
                  {canMembers && <button type="button" aria-label={`Tirar ${p?.name ?? id}`} onClick={() => setMembers(members.filter((m) => m !== id))} style={{ border: 0, background: "transparent", color: "inherit", cursor: "pointer", padding: 0, display: "flex" }}><Icon name="x" size={13} /></button>}
                </span>
              );
            })}
          </div>
          {canMembers && (
            <>
              <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Digite 3 letras do nome ou usuário para adicionar" aria-label="Buscar técnico" />
              {found.length > 0 && (
                <ul className="card" style={{ listStyle: "none", margin: 0, padding: 4 }}>
                  {found.map((p) => (
                    <li key={p.id}>
                      <button type="button" onClick={() => { setMembers([...members, p.id]); setQ(""); }}
                        style={{ width: "100%", textAlign: "left", border: 0, background: "transparent", padding: "7px 10px", borderRadius: 8, cursor: "pointer", font: "inherit", color: "var(--text)" }}>
                        <strong style={{ fontSize: 13 }}>{p.device!.username}</strong> <span className="muted" style={{ fontSize: 12 }}>· {p.name}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              <button type="button" className="btn btn-primary" style={{ alignSelf: "flex-end" }} disabled={busy || JSON.stringify([...members].sort()) === JSON.stringify([...(obj.members ?? [])].sort())} onClick={() => void saveMembers()}>Salvar membros</button>
            </>
          )}
        </div>
      )}
    </form>
  );
}
