import { useEffect, useRef, useState, type FormEvent } from "react";
import QRCode from "qrcode";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { Brand } from "../components/Logo";

type Step = "password" | "totp" | "setup" | "recovery" | "codes";

export function Login() {
  const { refresh } = useAuth();
  const [step, setStep] = useState<Step>("password");
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [setup, setSetup] = useState<{ uri: string; secret: string } | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const qrRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (step === "setup" && setup && qrRef.current) {
      void QRCode.toCanvas(qrRef.current, setup.uri, { width: 200, margin: 0 });
    }
  }, [step, setup]);

  async function run(fn: () => Promise<void>) {
    setError("");
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Não foi possível conectar à API.");
      if (e instanceof ApiError && e.status === 401 && step !== "password" && /expirada/.test(e.message)) {
        setStep("password");
      }
    } finally {
      setBusy(false);
    }
  }

  const submitPassword = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await api.post<{ next: string; otpauth_uri?: string; secret?: string }>("/api/auth/login", { login, password });
      setPassword("");
      setCode("");
      if (r.next === "totp_setup" && r.otpauth_uri && r.secret) {
        setSetup({ uri: r.otpauth_uri, secret: r.secret });
        setStep("setup");
      } else {
        setStep("totp");
      }
    });
  };

  const submitCode = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      if (step === "recovery") {
        await api.post("/api/auth/recovery", { code });
        await refresh();
        return;
      }
      const r = await api.post<{ recovery_codes?: string[] }>("/api/auth/totp", { code });
      if (r.recovery_codes?.length) {
        setRecoveryCodes(r.recovery_codes);
        setStep("codes");
        return;
      }
      await refresh();
    });
  };

  return (
    <main className="login-wrap">
      <div className="card login-card">
        <Brand />

        {step === "password" && (
          <form onSubmit={submitPassword} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <h1 style={{ fontSize: 22 }}>Entrar</h1>
            <label className="field">
              <span>Login</span>
              <input className="input" autoComplete="username" required placeholder="usuario@dominio" value={login} onChange={(e) => setLogin(e.target.value.trim())} />
            </label>
            <label className="field">
              <span>Senha</span>
              <input className="input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
            {error && <div className="alert alert-err" role="alert">{error}</div>}
            <button className="btn btn-primary" disabled={busy}>Continuar</button>
          </form>
        )}

        {step === "setup" && setup && (
          <form onSubmit={submitCode} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <h1 style={{ fontSize: 22 }}>Ative o código de acesso (TOTP)</h1>
            <p className="muted" style={{ margin: 0 }}>
              Leia o QR Code com um app autenticador (Google Authenticator, Microsoft Authenticator, Authy, Bitwarden…).
              Este código é só do painel: o acesso aos equipamentos tem usuário, senha e TOTP próprios.
            </p>
            <canvas ref={qrRef} className="qr" aria-label="QR Code para o app autenticador" />
            <details>
              <summary className="muted" style={{ cursor: "pointer" }}>Não consigo ler o QR Code</summary>
              <p className="mono" style={{ wordBreak: "break-all", margin: "8px 0 0" }}>{setup.secret}</p>
            </details>
            <label className="field">
              <span>Código de 6 dígitos</span>
              <input className="input mono" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" required value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
            </label>
            {error && <div className="alert alert-err" role="alert">{error}</div>}
            <button className="btn btn-primary" disabled={busy}>Ativar e entrar</button>
          </form>
        )}

        {(step === "totp" || step === "recovery") && (
          <form onSubmit={submitCode} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <h1 style={{ fontSize: 22 }}>{step === "totp" ? "Código de acesso" : "Código de recuperação"}</h1>
            <label className="field">
              <span>{step === "totp" ? "Código de 6 dígitos do app autenticador" : "Um dos códigos de recuperação (xxxx-xxxx-xxxx-xxxx)"}</span>
              <input className="input mono" autoComplete="one-time-code" inputMode={step === "totp" ? "numeric" : "text"} required value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
            </label>
            {error && <div className="alert alert-err" role="alert">{error}</div>}
            <button className="btn btn-primary" disabled={busy}>Entrar</button>
            <button type="button" className="btn" onClick={() => { setCode(""); setError(""); setStep(step === "totp" ? "recovery" : "totp"); }}>
              {step === "totp" ? "Perdi o celular: usar código de recuperação" : "Voltar ao código do app"}
            </button>
          </form>
        )}

        {step === "codes" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <h1 style={{ fontSize: 22 }}>Guarde seus códigos de recuperação</h1>
            <div className="alert alert-warn">
              Cada código funciona uma única vez, caso você perca o celular. Eles não serão mostrados de novo: guarde num cofre de senhas.
            </div>
            <div className="codes">{recoveryCodes.map((c) => <span key={c}>{c}</span>)}</div>
            <button className="btn" type="button" onClick={() => void navigator.clipboard?.writeText(recoveryCodes.join("\n"))}>Copiar códigos</button>
            <button className="btn btn-primary" type="button" onClick={() => void refresh()}>Já guardei, continuar</button>
          </div>
        )}
      </div>
    </main>
  );
}
