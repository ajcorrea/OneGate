import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type AuditEntry, type Customer } from "../api";
import { useAuth } from "../auth";
import { CustomerBadge } from "../components/CustomerBadge";
import { AuditTable } from "./Audit";

export function Overview() {
  const { me } = useAuth();
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);

  useEffect(() => {
    api.get<Customer[]>("/api/customers").then(setCustomers).catch(() => {});
    api.get<AuditEntry[]>("/api/audit?limit=8").then(setAudit).catch(() => {});
  }, []);
  const byId = useMemo(() => Object.fromEntries(customers.map((c) => [c.id, c])), [customers]);
  const active = customers.filter((c) => c.active);
  const withMFA = active.filter((c) => c.mfa === "totp").length;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Visão geral</h1>
          <p>Olá, {me?.name.split(" ")[0]}. {me?.is_admin ? "Você vê todos os clientes." : `Você tem acesso a ${customers.length} cliente(s).`}</p>
        </div>
      </div>

      <div className="grid-kpi">
        <div className="card kpi"><span className="kpi-label">Clientes ativos</span><span className="kpi-value">{active.length}</span></div>
        <div className="card kpi"><span className="kpi-label">Com MFA (TOTP) por padrão</span><span className="kpi-value">{withMFA}<span className="muted" style={{ fontSize: 15 }}> / {active.length}</span></span></div>
        <div className="card kpi"><span className="kpi-label">Servidores com agente</span><span className="kpi-value muted">—</span><span className="muted" style={{ fontSize: 12.5 }}>Agente chega no dia 4</span></div>
        <div className="card kpi"><span className="kpi-label">Equipamentos AAA</span><span className="kpi-value muted">—</span><span className="muted" style={{ fontSize: 12.5 }}>Cadastro chega no dia 7</span></div>
      </div>

      <div className="row" style={{ alignItems: "flex-start", gap: 16 }}>
        <section className="card card-pad" style={{ flex: "1 1 320px", display: "flex", flexDirection: "column", gap: 12 }}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <h2>Clientes</h2>
            <Link to="/clientes" style={{ fontWeight: 600, fontSize: 13 }}>Ver todos</Link>
          </div>
          <div className="row" style={{ gap: 8 }}>
            {customers.map((c) => <CustomerBadge key={c.id} code={c.code} name={c.name} color={c.color} />)}
            {customers.length === 0 && <span className="muted">Nenhum cliente ainda.</span>}
          </div>
        </section>
        <section className="card" style={{ flex: "2 1 560px", minWidth: 0 }}>
          <div className="row card-pad" style={{ justifyContent: "space-between", paddingBottom: 8 }}>
            <h2>Eventos recentes</h2>
            <Link to="/auditoria" style={{ fontWeight: 600, fontSize: 13 }}>Abrir auditoria</Link>
          </div>
          <AuditTable entries={audit} customers={byId} compact />
        </section>
      </div>
    </>
  );
}
