import { useTheme } from "../theme";

function luminance(hex: string): number {
  const n = parseInt(hex.slice(1), 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function lighten(hex: string, w: number): string {
  const n = parseInt(hex.slice(1), 16);
  const ch = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => Math.round(v + (255 - v) * w));
  return "#" + ch.map((v) => v.toString(16).padStart(2, "0")).join("");
}

/** Cores do quadrado do código: legíveis em qualquer cor de cliente e nos dois temas. */
export function badgeColors(color: string, dark: boolean): { bg: string; fg: string } {
  const bg = dark ? lighten(color, 0.45) : color;
  return { bg, fg: luminance(bg) > 0.35 ? "#0B1E44" : "#FFFFFF" };
}

export function CodeBox({ code, color, title }: { code: string; color: string; title?: string }) {
  const { dark } = useTheme();
  const c = badgeColors(color, dark);
  return (
    <span className="cbadge-code" style={{ background: c.bg, color: c.fg }} title={title}>
      {code}
    </span>
  );
}

/** Badge de identificação visual do cliente: código colorido + nome. */
export function CustomerBadge({ code, name, color }: { code: string; name: string; color: string }) {
  return (
    <span className="cbadge">
      <CodeBox code={code} color={color} />
      {name}
    </span>
  );
}
