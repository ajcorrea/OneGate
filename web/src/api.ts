// Cliente da API ONE GATE.

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new ApiError(res.status, data?.error ?? "Erro inesperado.");
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  del: <T>(path: string) => request<T>("DELETE", path, {}),
  post: <T>(path: string, body: unknown = {}) => request<T>("POST", path, body),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  put: <T>(path: string, body: unknown) => request<T>("PUT", path, body),
};

export const GLOBAL_DOMAIN = "onegate.systems";

export interface Me {
  id: string;
  login: string;
  name: string;
  domain: string;
  is_admin: boolean;
  global: boolean;
  platform: string[];
  customers: { customer_id: string; code: string; name: string; color: string; domain: string; functions: string[] }[];
}

export interface CatalogMenu {
  id: string;
  label: string;
  functions: { id: string; label: string; platform?: boolean }[];
}

export interface AccessType {
  id: string;
  key: string | null;
  name: string;
  description: string;
  scope: "global" | "customer";
  builtin: boolean;
  full_access: boolean;
  grants: string[];
}

export interface PanelGroup {
  id: string;
  name: string;
  customer_id: string | null;
  base_type_id: string;
  description: string;
  overrides: Record<string, "allow" | "deny">;
  members: string[];
}

export interface Decision {
  allowed: boolean;
  reason: string;
  chain: { level: string; value: string }[];
}

export interface Customer {
  id: string;
  code: string;
  name: string;
  domain: string;
  segment: string;
  color: string;
  mfa: "off" | "totp";
  trust_window_seconds: number;
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Person {
  id: string;
  name: string;
  email: string | null;
  phone: string | null;
  active: boolean;
  created_at: string;
  customer_id: string | null;
  domain: string;
  panel: {
    login: string;
    active: boolean;
    totp_enabled: boolean;
    last_login_at: string | null;
    access_type_id: string | null;
    group_ids: string[];
    customer_ids: string[];
    overrides: Record<string, "allow" | "deny">;
  } | null;
  device: {
    username: string;
    active: boolean;
    totp_configured: boolean;
    password_changed_at: string;
  } | null;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  customer_id: string | null;
  customer_code: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  details: Record<string, unknown>;
}

export const segments: Record<string, string> = {
  provedor: "Provedor de internet",
  empresa: "Empresa",
  saude: "Saúde",
  educacao: "Educação",
  governo: "Governo",
  industria: "Indústria",
  logistica: "Logística",
  varejo: "Varejo",
  outro: "Outro",
};

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
}

export function formatWindow(seconds: number): string {
  if (seconds === 0) return "sempre pedir";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return `${+(seconds / 3600).toFixed(1)} h`;
}
