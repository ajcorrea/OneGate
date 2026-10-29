import { useEffect, useMemo, useState } from "react";
import { api, ApiError, formatDate, type AuditEntry, type Customer } from "../api";
import { CustomerBadge } from "../components/CustomerBadge";

export const actionLabels: Record<string, string> = {
  login: "Login no painel",
  "login.falha": "Falha de login",
  "mfa.cadastrado": "TOTP cadastrado",
  "mfa.redefinido": "TOTP redefinido",
  "cliente.criado": "Cliente cadastrado",
  "cliente.alterado": "Cliente alterado",
  "equipe.criado": "Membro da equipe cadastrado",
  "equipe.alterado": "Membro da equipe alterado",
  "equipe.papel": "Acesso a cliente concedido",
  "equipe.papeis_definidos": "Acessos por cliente definidos",
};

export function describe(e: AuditEntry): string {
  const d = e.details ?? {};
  const parts = Object.entries(d)
    .filter(([k]) => k !== "total")
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`);
  return parts.join(" · ");
}

export function AuditTable({ entries, customers, compact = false }: { entries: AuditEntry[]; customers: Record<string, Customer>; compact?: boolean }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>Quando</th><th>Quem</th><th>Cliente</th><th>Ação</th>{!compact && <th>Detalhes</th>}</tr>
        </thead>
        <tbody>
          {entries.map((e) => {
            const c = e.customer_id ? customers[e.customer_id] : undefined;
            return (
              <tr key={e.id}>
                <td className="mono muted" style={{ fontSize: 12.5, whiteSpace: "nowrap" }}>{formatDate(e.at)}</td>
                <td><span style={{ display: "flex", flexDirection: "column" }}>{e.actor}{!compact && e.ip && <span className="muted mono" style={{ fontSize: 11.5 }}>{e.ip}</span>}</span></td>
                <td>{c ? <CustomerBadge code={c.code} name={c.name} color={c.color} /> : <span className="muted">Plataforma</span>}</td>
                <td>
                  <span className={"pill " + (e.action.includes("falha") ? "pill-err" : e.action.startsWith("mfa") ? "pill-warn" : "pill-info")}>
                    {actionLabels[e.action] ?? e.action}
                  </span>
                </td>
                {!compact && <td className="muted" style={{ fontSize: 12.5 }}>{describe(e)}</td>}
              </tr>
            );
          })}
          {entries.length === 0 && <tr><td colSpan={compact ? 4 : 5} className="muted">Nenhum evento.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

export function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api.get<Customer[]>("/api/customers").then(setCustomers).catch(() => {});
  }, []);
  useEffect(() => {
    api.get<AuditEntry[]>(`/api/audit?limit=200${filter ? `&customer_id=${filter}` : ""}`)
      .then(setEntries)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Erro ao carregar."));
  }, [filter]);
  const byId = useMemo(() => Object.fromEntries(customers.map((c) => [c.id, c])), [customers]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Auditoria</h1>
          <p>Toda ação administrativa fica registrada e não pode ser alterada. Você só vê eventos dos clientes em que tem acesso.</p>
        </div>
        <label className="field" style={{ minWidth: 240 }}>
          <span className="sr-only">Filtrar por cliente</span>
          <select className="input" value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="">Todos os clientes</option>
            {customers.map((c) => <option key={c.id} value={c.id}>{c.code} · {c.name}</option>)}
          </select>
        </label>
      </div>
      {error && <div className="alert alert-err">{error}</div>}
      <section className="card"><AuditTable entries={entries} customers={byId} /></section>
    </>
  );
}
