import { useRef, useState } from "react";
import { Eye, EyeOff, Flame, ShieldCheck } from "lucide-react";
import { login } from "../api";
import { Wordmark } from "./Wordmark";
import "./LoginPage.css";

const FEATURES = [
  { icon: Flame, label: "Isolated detonation" },
  { icon: Eye, label: "Explainable verdicts" },
  { icon: ShieldCheck, label: "Tamper-evident audit" },
];

export function LoginPage({ onLogin }: { onLogin: (user: { username: string; role: string }) => void }) {
  const usernameRef = useRef<HTMLInputElement>(null);
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [capsLockOn, setCapsLockOn] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const username = usernameRef.current?.value.trim() ?? "";
    if (!username || !password) return;
    setBusy(true);
    setError(null);
    try {
      const user = await login(username, password);
      onLogin(user);
    } catch (e) {
      setError(e instanceof Error ? e.message : "login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <aside className="login-aside">
        <div className="login-aside__scanline" aria-hidden="true" />
        <div className="login-aside__content">
          <Wordmark size={40} className="login-aside__wordmark" />
          <p className="login-aside__tagline">Detonate in the shadow. Protect the real.</p>
          <ul className="login-aside__features">
            {FEATURES.map(({ icon: Icon, label }) => (
              <li key={label}>
                <Icon size={16} aria-hidden="true" />
                {label}
              </li>
            ))}
          </ul>
        </div>
      </aside>

      <div className="login-form-side">
        <div className="login-form-side__wordmark">
          <Wordmark size={32} />
        </div>
        <form className="login-card" onSubmit={handleSubmit}>
          <h1>Sign in</h1>
          <p className="login-card__subtitle">Enter your credentials to continue</p>

          <div className="login-field">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              name="username"
              autoComplete="username"
              ref={usernameRef}
              autoFocus
              disabled={busy}
            />
          </div>

          <div className="login-field">
            <label htmlFor="password">Password</label>
            <div className="login-field__password">
              <input
                id="password"
                name="password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyUp={(e) => setCapsLockOn(e.getModifierState("CapsLock"))}
                disabled={busy}
              />
              <button
                type="button"
                className="login-field__toggle"
                aria-label={showPassword ? "Hide password" : "Show password"}
                onClick={() => setShowPassword((s) => !s)}
              >
                {showPassword ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />}
              </button>
            </div>
            {capsLockOn && <p className="login-field__hint">Caps Lock is on</p>}
          </div>

          <button type="submit" className="login-submit" disabled={busy}>
            {busy && <span className="spinner" aria-hidden="true" />}
            {busy ? "Signing in…" : "Sign in"}
          </button>
          {error && <p className="error-text">{error}</p>}
        </form>
      </div>
    </div>
  );
}
