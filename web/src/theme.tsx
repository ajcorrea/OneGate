import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

type ThemeCtx = { dark: boolean; toggle: () => void };
const Ctx = createContext<ThemeCtx>({ dark: false, toggle: () => {} });

function initial(): boolean {
  try {
    const saved = localStorage.getItem("onegate-theme");
    if (saved) return saved === "dark";
  } catch {
    /* sem localStorage */
  }
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [dark, setDark] = useState(initial);
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    try {
      localStorage.setItem("onegate-theme", dark ? "dark" : "light");
    } catch {
      /* sem localStorage */
    }
  }, [dark]);
  return <Ctx.Provider value={{ dark, toggle: () => setDark((d) => !d) }}>{children}</Ctx.Provider>;
}

export const useTheme = () => useContext(Ctx);
