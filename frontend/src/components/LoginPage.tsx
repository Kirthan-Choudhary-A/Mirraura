import { useRef, useState } from "react";
import { login } from "../api";

export function LoginPage({ onLogin }: { onLogin: (user: { username: string; role: string }) => void }) {
  const usernameRef = useRef<HTMLInputElement>(null);
  const [password, setPassword] = useState("");
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
      <form className="panel login-form" onSubmit={handleSubmit}>
        <h1>Mirraura</h1>
        <p className="app-header__subtitle">Sign in to continue</p>
        <label htmlFor="username">Username</label>
        <input
          id="username"
          name="username"
          autoComplete="username"
          ref={usernameRef}
          autoFocus
          disabled={busy}
        />
        <label htmlFor="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyUp={(e) => setCapsLockOn(e.getModifierState("CapsLock"))}
          disabled={busy}
        />
        {capsLockOn && <p className="login-form__hint">Caps Lock is on</p>}
        <button type="submit" className="run-button" disabled={busy}>
          {busy && <span className="spinner" aria-hidden="true" />}
          {busy ? "Signing in…" : "Sign in"}
        </button>
        {error && <p className="error-text">{error}</p>}
      </form>
    </div>
  );
}
