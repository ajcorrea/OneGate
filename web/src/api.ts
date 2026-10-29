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

export type Module = "aaa" | "servers" | "commands" | "audit";
export type Level = "read" | "write";

export const moduleLabels: Record<Module, string> = {
  aaa: "Acesso à rede (AAA)",
  servers: "Servidores",
  commands: "Comandos em massa",
  audit: "Auditoria",
};

export interface Me {
  id: string;
  email: string;
  name: string;
  is_admin: boolean;
  customers: { customer_id: string; code: string; name: string; color: string; modules: Partial<Record<Module, Level>> }[];
}

export interface Customer {
  id: string;
  code: string;
  name: string;
  segment: string;
  color: string;
  mfa: "off" | "totp";
  trust_window_seconds: number;
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Permission {
  customer_id: string;
  module: Module;
  level: Level;
}

export interface Person {
  id: string;
  name: string;
  email: string | null;
  phone: string | null;
  active: boolean;
  created_at: string;
  panel: {
    login_email: string;
    is_admin: boolean;
    active: boolean;
    totp_enabled: boolean;
    last_login_at: string | null;
    permissions: Permission[];
  } | null;
  device: {
    username: string;
    active: boolean;
    totp_configured: boolean;
    password_changed_at: string;
    customers: string[];
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

/** Papéis prontos: atalhos para preencher a matriz de permissões de um cliente. */
export const presets: { id: string; label: string; modules: Partial<Record<Module, Level>> }[] = [
  { id: "none", label: "Sem acesso", modules: {} },
  { id: "viewer", label: "Leitura", modules: { aaa: "read", servers: "read", commands: "read", audit: "read" } },
  { id: "operator", label: "Operador", modules: { aaa: "read", servers: "write", commands: "write", audit: "read" } },
  { id: "admin", label: "Administrador do cliente", modules: { aaa: "write", servers: "write", commands: "write", audit: "read" } },
];

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
}

export function formatWindow(seconds: number): string {
  if (seconds === 0) return "sempre pedir";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return `${+(seconds / 3600).toFixed(1)} h`;
}
