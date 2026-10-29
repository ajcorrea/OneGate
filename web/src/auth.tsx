import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiError, type Me } from "./api";

type AuthCtx = {
  me: Me | null;
  /** A função vale na plataforma (customerId omitido) ou no cliente informado. */
  can: (fn: string, customerId?: string) => boolean;
  /** A função vale na plataforma ou em algum cliente. */
  canAny: (fn: string) => boolean;
  loading: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
};

const Ctx = createContext<AuthCtx>({ me: null, can: () => false, canAny: () => false, loading: true, refresh: async () => {}, logout: async () => {} });

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setMe(await api.get<Me>("/api/auth/me"));
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 401)) console.error(e);
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    await api.post("/api/auth/logout").catch(() => {});
    setMe(null);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const can = (fn: string, customerId?: string) => {
    if (!me) return false;
    if (me.is_admin) return true;
    if (!customerId) return me.platform.includes(fn);
    return me.customers.find((c) => c.customer_id === customerId)?.functions.includes(fn) ?? false;
  };
  const canAny = (fn: string) => !!me && (me.is_admin || me.platform.includes(fn) || me.customers.some((c) => c.functions.includes(fn)));
  return <Ctx.Provider value={{ me, can, canAny, loading, refresh, logout }}>{children}</Ctx.Provider>;
}

export const useAuth = () => useContext(Ctx);
