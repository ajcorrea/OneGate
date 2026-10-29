import { useState } from "react";
import type { CatalogMenu } from "../api";
import { Icon } from "./Icon";

type Effect = "allow" | "deny";

const segBase: React.CSSProperties = {
  minHeight: 30, padding: "0 10px", border: 0, borderRadius: 6, font: "inherit", fontSize: 12, cursor: "pointer", background: "transparent", color: "var(--muted)",
};

function Seg({ label, options, value, onChange, disabled }: { label: string; options: { v: string; label: string; tone: "ok" | "err" | "muted" }[]; value: string; onChange: (v: string) => void; disabled?: boolean }) {
  return (
    <span role="radiogroup" aria-label={label} style={{ display: "inline-flex", padding: 3, gap: 3, borderRadius: 8, border: "1px solid var(--border)", background: "var(--sunk)" }}>
      {options.map((o) => {
        const on = o.v === value;
        const color = o.tone === "ok" ? "var(--ok)" : o.tone === "err" ? "var(--err)" : "var(--muted)";
        const bg = o.tone === "ok" ? "var(--ok-bg)" : o.tone === "err" ? "var(--err-bg)" : "var(--surface)";
        return (
          <button key={o.v} type="button" role="radio" aria-checked={on} disabled={disabled} onClick={() => onChange(o.v)}
            style={{ ...segBase, cursor: disabled ? "not-allowed" : "pointer", fontWeight: on ? 700 : 500, background: on ? bg : "transparent", color: on ? color : "var(--muted)" }}>
            {o.label}
          </button>
        );
      })}
    </span>
  );
}

/**
 * Árvore de menus e funções do painel.
 * - mode "grants": tipo de acesso (Incluir / Não incluir).
 * - mode "overrides": grupo ou usuário (Herdar / Permitir / Negar), com a coluna "efetivo" opcional.
 */
export function PermissionTree(props: {
  catalog: CatalogMenu[];
  mode: "grants" | "overrides";
  grants?: Set<string>;
  overrides?: Record<string, Effect>;
  onGrants?: (s: Set<string>) => void;
  onOverrides?: (o: Record<string, Effect>) => void;
  effective?: Record<string, { allowed: boolean; reason: string }>;
  disabled?: boolean;
  /** Funções de plataforma ficam bloqueadas (tipos e grupos por cliente). */
  customerScope?: boolean;
}) {
  const [open, setOpen] = useState<Record<string, boolean>>({ aaa: true, admin: true });
  const { catalog, mode, grants = new Set(), overrides = {}, effective, disabled, customerScope } = props;

  const setOverride = (fn: string, v: string) => {
    const next = { ...overrides };
    if (v === "") delete next[fn];
    else next[fn] = v as Effect;
    props.onOverrides?.(next);
  };
  const setGrant = (fn: string, v: boolean) => {
    const next = new Set(grants);
    if (v) next.add(fn);
    else next.delete(fn);
    props.onGrants?.(next);
  };
  const bulk = (menu: CatalogMenu, v: string) => {
    if (mode === "grants") {
      const next = new Set(grants);
      for (const f of menu.functions) if (!(customerScope && f.platform)) (v === "allow" ? next.add(f.id) : next.delete(f.id));
      props.onGrants?.(next);
    } else {
      const next = { ...overrides };
      for (const f of menu.functions) {
        if (customerScope && f.platform) continue;
        if (v === "") delete next[f.id];
        else next[f.id] = v as Effect;
      }
      props.onOverrides?.(next);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {catalog.map((menu) => {
        const isOpen = !!open[menu.id];
        const fns = menu.functions;
        const count = fns.filter((f) => (effective ? effective[f.id]?.allowed : mode === "grants" ? grants.has(f.id) : overrides[f.id] === "allow")).length;
        return (
          <div key={menu.id} style={{ borderBottom: "1px solid var(--border)" }}>
            <div className="row" style={{ padding: "10px 4px", gap: 10 }}>
              <button type="button" className="btn btn-icon" style={{ width: 32, minHeight: 32, height: 32 }} aria-label={(isOpen ? "Recolher " : "Expandir ") + menu.label}
                onClick={() => setOpen({ ...open, [menu.id]: !isOpen })}>
                <span style={{ display: "inline-flex", transform: `rotate(${isOpen ? 90 : 0}deg)`, transition: "transform .15s" }}><Icon name="chevron" size={14} /></span>
              </button>
              <span style={{ flex: 1, minWidth: 160, display: "flex", flexDirection: "column" }}>
                <strong>{menu.label}</strong>
                <span className="muted" style={{ fontSize: 12 }}>{count} de {fns.length} {effective ? "permitidas" : mode === "grants" ? "incluídas" : "com Permitir"}</span>
              </span>
              {!disabled && (
                <span className="row" style={{ gap: 4 }}>
                  {mode === "grants" ? (
                    <>
                      <button type="button" className="btn" style={{ minHeight: 30, fontSize: 12, color: "var(--ok)" }} onClick={() => bulk(menu, "allow")}>Incluir todos</button>
                      <button type="button" className="btn" style={{ minHeight: 30, fontSize: 12 }} onClick={() => bulk(menu, "")}>Limpar</button>
                    </>
                  ) : (
                    <>
                      <button type="button" className="btn" style={{ minHeight: 30, fontSize: 12, color: "var(--ok)" }} onClick={() => bulk(menu, "allow")}>Permitir todos</button>
                      <button type="button" className="btn" style={{ minHeight: 30, fontSize: 12, color: "var(--err)" }} onClick={() => bulk(menu, "deny")}>Negar todos</button>
                      <button type="button" className="btn" style={{ minHeight: 30, fontSize: 12 }} onClick={() => bulk(menu, "")}>Herdar todos</button>
                    </>
                  )}
                </span>
              )}
            </div>
            {isOpen && (
              <div style={{ padding: "0 4px 10px 46px" }}>
                {fns.map((f) => {
                  const locked = disabled || (customerScope && f.platform);
                  const eff = effective?.[f.id];
                  return (
                    <div key={f.id} className="row" style={{ padding: "7px 0", borderTop: "1px dashed var(--border)", gap: 10 }}>
                      <span style={{ flex: "1 1 220px", minWidth: 0, display: "flex", flexDirection: "column" }}>
                        <span style={{ fontSize: 13.5 }}>{f.label}</span>
                        <span className="muted" style={{ fontSize: 11.5 }}>
                          {customerScope && f.platform ? "Função da plataforma: não vale por cliente" : eff ? eff.reason : f.id}
                        </span>
                      </span>
                      {mode === "grants" ? (
                        <Seg label={f.label} disabled={locked} value={grants.has(f.id) ? "allow" : ""} onChange={(v) => setGrant(f.id, v === "allow")}
                          options={[{ v: "allow", label: "Incluir", tone: "ok" }, { v: "", label: "Não incluir", tone: "muted" }]} />
                      ) : (
                        <Seg label={f.label} disabled={locked} value={overrides[f.id] ?? ""} onChange={(v) => setOverride(f.id, v)}
                          options={[{ v: "", label: "Herdar", tone: "muted" }, { v: "allow", label: "Permitir", tone: "ok" }, { v: "deny", label: "Negar", tone: "err" }]} />
                      )}
                      {eff && <span className={"pill " + (eff.allowed ? "pill-ok" : "pill-err")} style={{ minWidth: 84, justifyContent: "center" }}>{eff.allowed ? "Permitido" : "Negado"}</span>}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
