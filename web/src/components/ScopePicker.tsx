import { useEffect } from "react";
import { useAuth } from "../auth";

/**
 * Escolha do escopo das telas AAA: um cliente (onde a pessoa tem a função) ou o escopo global.
 * value "" = global.
 */
export function ScopePicker({ fn, value, onChange, allowGlobal, label = "Cliente" }: {
  fn: string;
  value: string | null;
  onChange: (v: string) => void;
  allowGlobal?: boolean;
  label?: string;
}) {
  const { me, can } = useAuth();
  const customers = (me?.customers ?? []).filter((c) => can(fn, c.customer_id));
  const globalOk = !!allowGlobal && can(fn);
  useEffect(() => {
    if (value !== null) return;
    if (customers.length) onChange(customers[0].customer_id);
    else if (globalOk) onChange("");
  }, [value, customers, globalOk, onChange]);
  return (
    <label className="field" style={{ minWidth: 260 }}>
      <span>{label}</span>
      <select className="input" value={value ?? ""} onChange={(e) => onChange(e.target.value)}>
        {globalOk && <option value="">Global (todos os clientes)</option>}
        {customers.map((c) => (
          <option key={c.customer_id} value={c.customer_id}>{c.code} · {c.name} (@{c.domain})</option>
        ))}
      </select>
    </label>
  );
}

export function useCustomerInfo(id: string | null) {
  const { me } = useAuth();
  return me?.customers.find((c) => c.customer_id === id) ?? null;
}
