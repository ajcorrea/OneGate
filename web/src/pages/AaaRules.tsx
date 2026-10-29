import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  api, ApiError, formatDate, ruleMissing,
  type AAADevice, type AAARule, type RefLabel, type RuleField, type RulesResponse, type SearchItem, type SimResponse,
} from "../api";
import { useAuth } from "../auth";
import { Icon } from "../components/Icon";
import { ScopePicker, useCustomerInfo } from "../components/ScopePicker";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : "Erro inesperado.";
}

type Labels = Record<string, RefLabel>;

const slots: { field: RuleField | "mfa"; title: string; required: boolean | "allow"; single?: boolean; hint: string }[] = [
  { field: "who", title: "Quem", required: true, hint: "Grupo, ou 3 letras do usuário" },
  { field: "where", title: "Onde (equipamentos)", required: true, hint: "Grupo, fabricante ou equipamento" },
  { field: "from", title: "De onde (IP de origem)", required: true, hint: "Rede ou faixa (10.0.0.0/24)" },
  { field: "what", title: "O que pode fazer", required: "allow", single: true, hint: "Perfil de comandos" },
  { field: "when", title: "Quando", required: false, hint: "Vazio = Sempre" },
  { field: "mfa", title: "MFA", required: false, hint: "" },
];

const mfaLabels: Record<AAARule["mfa"], string> = { device: "Segue o equipamento", totp: "TOTP obrigatório", none: "Sem MFA" };

let tmpSeq = 0;
const newRule = (): AAARule => ({ id: `novo-${++tmpSeq}`, customer_id: null, name: "Nova regra", action: "allow", who: [], where: [], from: [], what: "", when: [], mfa: "device" });

function toInput(r: AAARule) {
  return { id: r.id.startsWith("novo-") ? "" : r.id, name: r.name, action: r.action, who: r.who, where: r.where, from: r.from, what: r.what, when: r.when, mfa: r.mfa };
}

export function AaaRules() {
  const { can } = useAuth();
  const [scope, setScope] = useState<string | null>(null);
  const [data, setData] = useState<RulesResponse | null>(null);
  const [rules, setRules] = useState<AAARule[]>([]);
  const [labels, setLabels] = useState<Labels>({});
  const [devices, setDevices] = useState<AAADevice[]>([]);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const cust = useCustomerInfo(scope);
  const isGlobal = scope === "";

  const load = useCallback(async (sc: string) => {
    const q = sc ? `?customer_id=${sc}` : "";
    const d = await api.get<RulesResponse>(`/api/aaa/rules${q}`);
    setData(d);
    setLabels((l) => ({ ...l, ...d.labels }));
    const view = sc ? d.customer! : d.global;
    setRules(view.rules);
    if (sc && can("aaa.devices.view", sc)) setDevices(await api.get<AAADevice[]>(`/api/aaa/devices?customer_id=${sc}`));
    else setDevices([]);
  }, [can]);

  useEffect(() => {
    if (scope === null) return;
    setMsg(null);
    setData(null);
    load(scope).catch((e) => setMsg({ ok: false, text: errMsg(e) }));
  }, [scope, load]);

  const view = data ? (isGlobal ? data.global : data.customer) : undefined;
  const saved = view?.rules ?? [];
  const dirty = JSON.stringify(rules.map(toInput)) !== JSON.stringify(saved.map(toInput));
  const editable = !!view?.can_edit;
  const offset = isGlobal ? 0 : data?.global.rules.length ?? 0;

  const save = async () => {
    setBusy(true);
    setMsg(null);
    try {
      await api.put(`/api/aaa/rules${scope ? `?customer_id=${scope}` : ""}`, { rules: rules.map(toInput) });
      await load(scope!);
      setMsg({ ok: true, text: "Rascunho salvo. Nada mudou nos Edges: confira as diferenças e publique quando estiver pronto." });
    } catch (e) {
      setMsg({ ok: false, text: errMsg(e) });
    } finally {
      setBusy(false);
    }
  };

  const update = (i: number, r: AAARule) => setRules((rs) => rs.map((x, j) => (j === i ? r : x)));
  const move = (from: number, to: number) =>
    setRules((rs) => {
      if (to < 0 || to >= rs.length || from === to) return rs;
      const c = [...rs];
      const [x] = c.splice(from, 1);
      c.splice(to, 0, x);
      return c;
    });
  const dragFrom = useRef<number | null>(null);

  return (
    <>
      <div className="page-head">
        <div style={{ maxWidth: 820 }}>
          <h1>Regras de acesso (AAA)</h1>
          <p>
            Quem pode entrar em quais equipamentos, de onde, com que comandos, quando e com qual MFA. A <strong>primeira regra que corresponder decide</strong>;
            sem correspondência, o acesso é negado. Campo obrigatório vazio <strong>não libera nada</strong>: use os objetos pré-definidos (Todos, Nenhum, Sempre, Nunca).
          </p>
        </div>
        <ScopePicker fn="aaa.rules.view" value={scope} onChange={setScope} allowGlobal label="Escopo" />
      </div>
      {msg && <div className={"alert " + (msg.ok ? "alert-ok" : "alert-err")} role={msg.ok ? "status" : "alert"}>{msg.text}</div>}
      {!data && scope !== null && !msg && <p className="muted">Carregando…</p>}
      {data && view && (
        <div className="row" style={{ alignItems: "flex-start", gap: 16 }}>
          <div style={{ flex: "3 1 640px", minWidth: 0, display: "flex", flexDirection: "column", gap: 14 }}>
            {!isGlobal && (
              <details className="card" open={data.global.rules.length > 0 && data.global.rules.length <= 3}>
                <summary className="card-pad" style={{ cursor: "pointer", paddingBottom: 14 }}>
                  <strong>Regras globais</strong> <span className="muted">· {data.global.rules.length} · avaliadas antes das do cliente · publicadas pela ON TELECOM</span>
                </summary>
                <div style={{ padding: "0 14px 14px", display: "flex", flexDirection: "column", gap: 10 }}>
                  {data.global.rules.length === 0 && <p className="muted" style={{ margin: 0 }}>Nenhuma regra global.</p>}
                  {data.global.rules.map((r, i) => (
                    <RuleCard key={r.id} rule={r} num={i + 1} labels={labels} editable={false} cid="" onChange={() => {}} />
                  ))}
                </div>
              </details>
            )}
            <div className="row" style={{ justifyContent: "space-between" }}>
              <h2>{isGlobal ? "Regras globais (valem em todos os clientes)" : `Regras de ${cust?.name ?? "cliente"}`} <span className="muted" style={{ fontWeight: 500 }}>· {rules.length}</span></h2>
              {editable && (
                <div className="row">
                  {dirty && <span className="pill pill-warn">Rascunho com alterações não salvas</span>}
                  <button type="button" className="btn" disabled={!dirty || busy} onClick={() => setRules(saved)}>Descartar</button>
                  <button type="button" className="btn btn-primary" disabled={!dirty || busy} onClick={() => void save()}>Salvar rascunho</button>
                </div>
              )}
            </div>
            {rules.length === 0 && <div className="card card-pad muted">Nenhuma regra neste escopo: todo acesso é negado (exceto o que as regras globais liberarem).</div>}
            {rules.map((r, i) => (
              <div key={r.id}
                onDragOver={(e) => {
                  if (dragFrom.current === null) return;
                  e.preventDefault();
                  if (dragFrom.current !== i) {
                    move(dragFrom.current, i);
                    dragFrom.current = i;
                  }
                }}>
                <RuleCard rule={r} num={offset + i + 1} labels={labels} editable={editable} cid={scope ?? ""}
                  onChange={(nr) => update(i, nr)}
                  onLabel={(ref, field, l) => setLabels((x) => ({ ...x, [field + "|" + ref]: l }))}
                  onRemove={() => setRules((rs) => rs.filter((_, j) => j !== i))}
                  onUp={i > 0 ? () => move(i, i - 1) : undefined}
                  onDown={i < rules.length - 1 ? () => move(i, i + 1) : undefined}
                  onDragStart={() => (dragFrom.current = i)}
                  onDragEnd={() => (dragFrom.current = null)} />
              </div>
            ))}
            {editable && (
              <button type="button" className="btn" style={{ borderStyle: "dashed", color: "var(--accent-text)" }} onClick={() => setRules((rs) => [...rs, { ...newRule(), customer_id: scope || null }])}>
                <Icon name="plus" /> Adicionar regra
              </button>
            )}
            <p className="muted" style={{ fontSize: 12.5, margin: 0 }}>
              Depois da última regra: <strong>negar</strong> (padrão). Arraste pelo ⠿ ou use as setas para mudar a ordem.
            </p>
          </div>
          <div style={{ flex: "1 1 320px", display: "flex", flexDirection: "column", gap: 14, minWidth: 0 }}>
            <PublishPanel view={view} dirty={dirty} scope={scope ?? ""} onDone={async (t) => { await load(scope!); setMsg({ ok: true, text: t }); }} onError={(t) => setMsg({ ok: false, text: t })} />
            {!isGlobal && <SimulatorPanel cid={scope!} devices={devices} dirty={dirty} />}
          </div>
        </div>
      )}
    </>
  );
}

function RuleCard({ rule, num, labels, editable, cid, onChange, onLabel, onRemove, onUp, onDown, onDragStart, onDragEnd }: {
  rule: AAARule; num: number; labels: Labels; editable: boolean; cid: string;
  onChange: (r: AAARule) => void;
  onLabel?: (ref: string, field: string, l: RefLabel) => void;
  onRemove?: () => void; onUp?: () => void; onDown?: () => void;
  onDragStart?: () => void; onDragEnd?: () => void;
}) {
  const cardRef = useRef<HTMLElement>(null);
  const missing = ruleMissing(rule);
  const deny = rule.action === "deny";
  const bar = missing.length ? "var(--warn)" : deny ? "var(--err)" : "var(--ok)";
  return (
    <article className="card" ref={cardRef}
      style={{ borderLeft: `4px solid ${bar}`, display: "flex", flexDirection: "column" }} aria-label={`Regra ${num}: ${rule.name}`}>
      <header className="row" style={{ padding: "10px 14px", gap: 8, borderBottom: "1px solid var(--border)" }}>
        {editable && (
          <span title="Arraste para reordenar" aria-hidden="true" draggable
            onDragStart={(e) => {
              e.dataTransfer.effectAllowed = "move";
              e.dataTransfer.setData("text/plain", rule.id);
              if (cardRef.current) e.dataTransfer.setDragImage(cardRef.current, 24, 20);
              onDragStart?.();
            }}
            onDragEnd={() => onDragEnd?.()}
            style={{ cursor: "grab", color: "var(--muted)", fontSize: 18, lineHeight: 1, userSelect: "none", padding: "0 2px" }}>⠿</span>
        )}
        <span className="mono" style={{ fontWeight: 700, color: "var(--muted)", minWidth: 28 }}>#{num}</span>
        {editable ? (
          <input className="input" aria-label="Nome da regra" value={rule.name} onChange={(e) => onChange({ ...rule, name: e.target.value })}
            style={{ flex: "1 1 200px", minHeight: 36, fontWeight: 600 }} />
        ) : (
          <strong style={{ flex: "1 1 200px" }}>{rule.name}</strong>
        )}
        {editable ? (
          <div role="radiogroup" aria-label="Ação" className="row" style={{ gap: 0, border: "1px solid var(--border)", borderRadius: 8, overflow: "hidden" }}>
            {(["allow", "deny"] as const).map((a) => (
              <button key={a} type="button" role="radio" aria-checked={rule.action === a} onClick={() => onChange({ ...rule, action: a })}
                style={{ minHeight: 34, padding: "0 12px", border: 0, font: "inherit", fontWeight: 600, fontSize: 13, cursor: "pointer",
                  background: rule.action === a ? (a === "allow" ? "var(--ok-bg)" : "var(--err-bg)") : "transparent",
                  color: rule.action === a ? (a === "allow" ? "var(--ok)" : "var(--err)") : "var(--muted)" }}>
                {a === "allow" ? "Permitir" : "Negar"}
              </button>
            ))}
          </div>
        ) : (
          <span className={"pill " + (deny ? "pill-err" : "pill-ok")}>{deny ? "Negar" : "Permitir"}</span>
        )}
        {missing.length > 0 && <span className="pill pill-warn" title="Regra incompleta é ignorada e não pode ser publicada">Incompleta: sem {missing.join(", ")}</span>}
        {editable && (
          <span className="row" style={{ gap: 2 }}>
            <button type="button" className="btn btn-icon" style={{ minHeight: 34, width: 34 }} disabled={!onUp} onClick={onUp} aria-label="Subir regra">↑</button>
            <button type="button" className="btn btn-icon" style={{ minHeight: 34, width: 34 }} disabled={!onDown} onClick={onDown} aria-label="Descer regra">↓</button>
            <button type="button" className="btn btn-icon btn-danger" style={{ minHeight: 34, width: 34 }} onClick={onRemove} aria-label="Remover regra"><Icon name="x" size={16} /></button>
          </span>
        )}
      </header>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 12, padding: 14 }}>
        {slots.map((sd) => {
          if (sd.field === "mfa") {
            return (
              <div key="mfa" className="field">
                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".04em" }}>MFA</span>
                {deny ? <span className="muted" style={{ fontSize: 13 }}>— (regra de negar)</span> : editable ? (
                  <select className="input" style={{ minHeight: 36 }} value={rule.mfa} aria-label="MFA" onChange={(e) => onChange({ ...rule, mfa: e.target.value as AAARule["mfa"] })}>
                    {Object.entries(mfaLabels).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                  </select>
                ) : <span style={{ fontSize: 13 }}>{mfaLabels[rule.mfa]}</span>}
              </div>
            );
          }
          const f = sd.field;
          if (f === "what" && deny) {
            return (
              <div key={f} className="field">
                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".04em" }}>{sd.title}</span>
                <span className="muted" style={{ fontSize: 13 }}>— (regra de negar)</span>
              </div>
            );
          }
          const values = f === "what" ? (rule.what ? [rule.what] : []) : rule[f];
          const req = sd.required === true || (sd.required === "allow" && !deny);
          return (
            <Slot key={f} field={f} title={sd.title} hint={sd.hint} required={req} values={values} labels={labels} editable={editable} cid={cid}
              onChange={(vs) => onChange(f === "what" ? { ...rule, what: vs[vs.length - 1] ?? "" } : { ...rule, [f]: vs })}
              onLabel={(ref, l) => onLabel?.(ref, f, l)} />
          );
        })}
      </div>
    </article>
  );
}

function Slot({ field, title, hint, required, values, labels, editable, cid, onChange, onLabel }: {
  field: RuleField; title: string; hint: string; required: boolean; values: string[]; labels: Labels; editable: boolean; cid: string;
  onChange: (v: string[]) => void; onLabel: (ref: string, l: RefLabel) => void;
}) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<SearchItem[]>([]);
  const [active, setActive] = useState(0);
  const timer = useRef<number>(undefined);
  const empty = values.length === 0;

  useEffect(() => {
    if (!open) return;
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      api.get<SearchItem[]>(`/api/aaa/search?customer_id=${cid}&field=${field}&q=${encodeURIComponent(q)}`)
        .then((xs) => { setItems(xs.filter((x) => !values.includes(x.ref))); setActive(0); })
        .catch(() => setItems([]));
    }, 180);
    return () => window.clearTimeout(timer.current);
  }, [q, open, cid, field, values]);

  const pick = (it: SearchItem) => {
    onLabel(it.ref, it);
    const pre = ["all", "none", "always", "never"];
    // Pré-definido substitui o resto; um objeto comum tira os pré-definidos.
    const next = pre.includes(it.ref) ? [it.ref] : [...values.filter((v) => !pre.includes(v)), it.ref];
    onChange(next);
    setQ("");
  };
  const lab = (ref: string) => labels[field + "|" + ref] ?? { label: ref, sub: "", kind: "" };
  const listId = useId();

  return (
    <div className="field" style={{ position: "relative" }}>
      <span style={{ fontSize: 12, fontWeight: 600, color: empty && required ? "var(--warn)" : "var(--muted)", textTransform: "uppercase", letterSpacing: ".04em" }}>
        {title}{required && empty ? " · obrigatório" : ""}
      </span>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, minHeight: 30, alignItems: "center" }}>
        {values.map((v) => {
          const l = lab(v);
          const neg = v === "none" || v === "never";
          return (
            <span key={v} title={l.sub} className="pill" style={{
              gap: 6, paddingRight: editable ? 4 : 9, fontWeight: 600,
              background: l.missing ? "var(--err-bg)" : l.pre ? (neg ? "var(--err-bg)" : "var(--sunk)") : "var(--accent-soft)",
              color: l.missing ? "var(--err)" : l.pre ? (neg ? "var(--err)" : "var(--text)") : "var(--accent-text)",
              border: l.pre ? "1px dashed var(--border)" : "1px solid transparent",
            }}>
              {l.label}
              {editable && (
                <button type="button" aria-label={`Remover ${l.label}`} onClick={() => onChange(values.filter((x) => x !== v))}
                  style={{ border: 0, background: "transparent", color: "inherit", cursor: "pointer", padding: 0, display: "flex" }}>
                  <Icon name="x" size={13} />
                </button>
              )}
            </span>
          );
        })}
        {empty && !editable && <span className="muted" style={{ fontSize: 13 }}>{field === "when" ? "Sempre" : "—"}</span>}
        {empty && editable && field === "when" && <span className="muted" style={{ fontSize: 12.5 }}>Sempre (padrão)</span>}
      </div>
      {editable && (
        <>
          <input className="input" style={{ minHeight: 36, fontSize: 13 }} placeholder={hint} value={q}
            role="combobox" aria-expanded={open} aria-controls={listId} aria-autocomplete="list" aria-label={`Adicionar em ${title}`}
            onFocus={() => setOpen(true)}
            onBlur={(e) => { const el = e.currentTarget; window.setTimeout(() => { if (document.activeElement !== el) setOpen(false); }, 150); }}
            onChange={(e) => { setQ(e.target.value); setOpen(true); }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, items.length - 1)); }
              if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
              if (e.key === "Enter" && items[active]) { e.preventDefault(); pick(items[active]); }
              if (e.key === "Escape") setOpen(false);
            }} />
          {open && (
            <ul id={listId} role="listbox" className="card" style={{ position: "absolute", top: "100%", left: 0, right: 0, zIndex: 20, margin: "4px 0 0", padding: 4, listStyle: "none", maxHeight: 280, overflowY: "auto", boxShadow: "0 10px 30px rgba(0,0,0,.18)" }}>
              {items.length === 0 && (
                <li className="muted" style={{ padding: "8px 10px", fontSize: 12.5 }}>
                  {field === "who" && q.trim().length < 3 ? "Digite 3 letras para buscar usuários." : "Nada encontrado."}
                </li>
              )}
              {items.map((it, i) => (
                <li key={it.ref} role="option" aria-selected={i === active}
                  onMouseDown={(e) => { e.preventDefault(); pick(it); }} onMouseEnter={() => setActive(i)}
                  style={{ padding: "7px 10px", borderRadius: 8, cursor: "pointer", background: i === active ? "var(--accent-soft)" : "transparent", display: "flex", flexDirection: "column" }}>
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{it.label}{it.pre && <span className="muted" style={{ fontWeight: 500 }}> · pré-definido</span>}</span>
                  <span className="muted" style={{ fontSize: 11.5 }}>{it.sub}</span>
                </li>
              ))}
              {field === "who" && q.trim().length > 0 && q.trim().length < 3 && items.length > 0 && (
                <li className="muted" style={{ padding: "6px 10px", fontSize: 11.5 }}>Usuários aparecem a partir de 3 letras.</li>
              )}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

function PublishPanel({ view, dirty, scope, onDone, onError }: {
  view: NonNullable<RulesResponse["customer"]>; dirty: boolean; scope: string;
  onDone: (msg: string) => Promise<void>; onError: (msg: string) => void;
}) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const pub = view.publication;
  const nothing = !!pub && view.diff.length === 0;
  const blocked = dirty || view.incomplete.length > 0 || nothing || !view.can_publish;
  const kindPill: Record<string, string> = { nova: "pill-ok", alterada: "pill-warn", removida: "pill-err", ordem: "pill-info" };

  const publish = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ version: number }>(`/api/aaa/publish${scope ? `?customer_id=${scope}` : ""}`, { note });
      setNote("");
      await onDone(`Versão ${r.version} publicada. Os Edges recebem a nova política na próxima sincronização.`);
    } catch (e) {
      onError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card card-pad" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <h2>Publicação</h2>
      <div style={{ fontSize: 13 }}>
        {pub ? (
          <>Publicada: <strong>versão {pub.version}</strong> <span className="muted">· {formatDate(pub.published_at)} · {pub.published_by}</span>{pub.note && <div className="muted">“{pub.note}”</div>}</>
        ) : <span className="muted">Nada publicado ainda: os Edges deste escopo não têm regras.</span>}
      </div>
      <div>
        <strong style={{ fontSize: 13 }}>Rascunho salvo × publicado</strong>
        <ul style={{ listStyle: "none", padding: 0, margin: "8px 0 0", display: "flex", flexDirection: "column", gap: 6 }}>
          {view.diff.length === 0 && <li className="muted" style={{ fontSize: 13 }}>{pub ? "Nenhuma diferença." : "Sem regras."}</li>}
          {view.diff.map((d, i) => (
            <li key={i} className="row" style={{ gap: 8, fontSize: 13 }}>
              <span className={"pill " + kindPill[d.kind]} style={{ minWidth: 72, justifyContent: "center" }}>{d.kind[0].toUpperCase() + d.kind.slice(1)}</span>
              {d.name}
            </li>
          ))}
        </ul>
      </div>
      {view.incomplete.length > 0 && (
        <div className="alert alert-warn">Regras incompletas impedem a publicação: {view.incomplete.join("; ")}.</div>
      )}
      {dirty && <div className="alert alert-warn">Salve o rascunho antes de publicar.</div>}
      {view.can_publish ? (
        <>
          <label className="field">
            <span>Nota da versão (opcional)</span>
            <input className="input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Ex.: libera terceirizados nas OLTs" />
          </label>
          <button type="button" className="btn btn-primary" disabled={blocked || busy} onClick={() => void publish()}>Publicar nos Edges</button>
        </>
      ) : <p className="muted" style={{ fontSize: 12.5, margin: 0 }}>Você pode ver, mas não publicar neste escopo.</p>}
    </section>
  );
}

function nowLocal() {
  const d = new Date();
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 16);
}

function SimulatorPanel({ cid, devices, dirty }: { cid: string; devices: AAADevice[]; dirty: boolean }) {
  const [mode, setMode] = useState<"draft" | "published">("draft");
  const [user, setUser] = useState("");
  const [dev, setDev] = useState("");
  const [src, setSrc] = useState("");
  const [at, setAt] = useState(nowLocal());
  const [cmd, setCmd] = useState("");
  const [res, setRes] = useState<SimResponse | null>(null);
  const [err, setErr] = useState("");
  const active = useMemo(() => devices.filter((d) => d.active), [devices]);
  useEffect(() => {
    if (!dev && active[0]) setDev(active[0].id);
  }, [active, dev]);

  const run = async () => {
    setErr("");
    try {
      setRes(await api.post<SimResponse>("/api/aaa/simulate", { customer_id: cid, mode, user, device_id: dev, source: src, at, command: cmd }));
    } catch (e) {
      setRes(null);
      setErr(errMsg(e));
    }
  };
  const st: Record<string, [string, string]> = { hit: ["var(--ok-bg)", "var(--ok)"], miss: ["var(--sunk)", "var(--muted)"], incomplete: ["var(--warn-bg)", "var(--warn)"], skip: ["transparent", "var(--muted)"] };

  return (
    <section className="card card-pad" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <h2>Simulador</h2>
      <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>Mesmo motor do Edge, sem tocar em equipamento nenhum.</p>
      <div role="radiogroup" aria-label="Regras a simular" className="row" style={{ gap: 0, border: "1px solid var(--border)", borderRadius: 8, overflow: "hidden", alignSelf: "flex-start" }}>
        {([["draft", "Rascunho salvo"], ["published", "Publicado"]] as const).map(([k, l]) => (
          <button key={k} type="button" role="radio" aria-checked={mode === k} onClick={() => setMode(k)}
            style={{ minHeight: 34, padding: "0 12px", border: 0, font: "inherit", fontSize: 13, fontWeight: 600, cursor: "pointer", background: mode === k ? "var(--accent-soft)" : "transparent", color: mode === k ? "var(--accent-text)" : "var(--muted)" }}>{l}</button>
        ))}
      </div>
      {dirty && mode === "draft" && <div className="alert alert-warn" style={{ fontSize: 12.5 }}>O simulador usa o rascunho salvo; salve para testar as alterações.</div>}
      <form className="form-grid" style={{ gridTemplateColumns: "1fr" }} onSubmit={(e) => { e.preventDefault(); void run(); }}>
        <label className="field"><span>Usuário</span><input className="input" value={user} onChange={(e) => setUser(e.target.value)} placeholder="pedro.lima ou pedro.lima@dominio" required /></label>
        <label className="field"><span>Equipamento</span>
          <select className="input" value={dev} onChange={(e) => setDev(e.target.value)} required>
            {active.length === 0 && <option value="">Nenhum equipamento ativo</option>}
            {active.map((d) => <option key={d.id} value={d.id}>{d.name} · {d.address}{d.vendor ? ` · ${d.vendor}` : ""}</option>)}
          </select>
        </label>
        <label className="field"><span>IP de origem do técnico</span><input className="input mono" value={src} onChange={(e) => setSrc(e.target.value)} placeholder="172.16.50.23" required /></label>
        <label className="field"><span>Data e hora (fuso do cliente)</span><input className="input" type="datetime-local" value={at} onChange={(e) => setAt(e.target.value)} /></label>
        <label className="field"><span>Comando (opcional)</span><input className="input mono" value={cmd} onChange={(e) => setCmd(e.target.value)} placeholder="display interface brief" /></label>
        <button className="btn btn-primary" disabled={!dev}>Simular</button>
      </form>
      {err && <div className="alert alert-err" role="alert">{err}</div>}
      {res && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }} aria-live="polite">
          <div className={"alert " + (res.result.allowed ? "alert-ok" : "alert-err")}>
            <strong>{res.result.allowed ? (res.command_checked ? "Permitido (login e comando)" : "Permitido") : "Negado"}</strong>
            <div style={{ fontSize: 13 }}>{res.result.reason}</div>
            {res.result.allowed && (
              <div style={{ fontSize: 12.5, marginTop: 4 }}>
                {res.result.username} · priv-lvl {res.result.priv_level} · MFA {res.result.mfa.required ? `TOTP (${res.result.mfa.reason})` : `não exigido (${res.result.mfa.reason})`}
              </div>
            )}
          </div>
          <div className="muted" style={{ fontSize: 12 }}>{res.at} · regras globais v{res.versions.global || "—"} · cliente v{res.versions.customer || "—"}{mode === "draft" ? " (rascunho)" : ""}</div>
          <ol style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 4 }}>
            {res.result.trail.map((s) => (
              <li key={s.num} className="row" style={{ gap: 8, fontSize: 12.5, flexWrap: "nowrap", alignItems: "flex-start" }}>
                <span className="mono" style={{ minWidth: 34, textAlign: "center", borderRadius: 6, padding: "1px 4px", fontWeight: 700, background: st[s.status][0], color: st[s.status][1] }}>#{s.num}</span>
                <span style={{ minWidth: 0 }}>
                  <span style={{ fontWeight: s.status === "hit" ? 700 : 500, color: s.status === "skip" ? "var(--muted)" : "var(--text)" }}>{s.name}</span>
                  <span className="muted"> · {s.scope === "global" ? "global" : "cliente"} · {s.note}</span>
                </span>
              </li>
            ))}
          </ol>
          {res.warnings && res.warnings.length > 0 && <div className="alert alert-warn" style={{ fontSize: 12.5 }}>{res.warnings.join(" · ")}</div>}
        </div>
      )}
    </section>
  );
}
