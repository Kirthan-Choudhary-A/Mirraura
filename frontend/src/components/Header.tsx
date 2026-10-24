import { useEffect, useState } from "react";
import { LogOut, Moon, ShieldAlert, ShieldCheck, Sun, Wifi, WifiOff } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { ConnectionState } from "../api";
import { getStoredTheme, setStoredTheme } from "../theme";
import type { Theme } from "../theme";
import { Badge } from "./Badge";
import type { BadgeTone } from "./Badge";
import { Wordmark } from "./Wordmark";
import "./Header.css";

const CONN_COPY: Record<ConnectionState, { label: string; tone: BadgeTone; icon: LucideIcon }> = {
  connecting: { label: "Connecting…", tone: "neutral", icon: Wifi },
  live: { label: "Live", tone: "neutral", icon: Wifi },
  offline: { label: "Offline — retrying", tone: "neutral", icon: WifiOff },
};

export function Header({
  user,
  connState,
  monitorIsolated,
  onLogout,
}: {
  user: { username: string; role: string };
  connState: ConnectionState;
  monitorIsolated: boolean;
  onLogout: () => void;
}) {
  const [theme, setTheme] = useState<Theme>(() => getStoredTheme());

  // Sync the DOM attribute to the stored preference on first mount — the
  // state initializer above already read it once, so reuse that value
  // rather than calling getStoredTheme() again.
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, []);

  function toggleTheme() {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setStoredTheme(next);
    document.documentElement.dataset.theme = next;
    setTheme(next);
  }

  const conn = CONN_COPY[connState];
  const ConnIcon = conn.icon;

  return (
    <header className="header">
      <div className="header__brand">
        <Wordmark />
        <p className="header__tagline">Shadow honeypot — live behavioral verdict engine</p>
      </div>

      <div className="header__status">
        <Badge tone={conn.tone} icon={<ConnIcon size={12} />}>
          {conn.label}
        </Badge>
        <Badge
          tone={monitorIsolated ? "compromised" : "normal"}
          icon={monitorIsolated ? <ShieldAlert size={12} /> : <ShieldCheck size={12} />}
        >
          {monitorIsolated ? "Isolated" : "Monitor connected"}
        </Badge>
      </div>

      <div className="header__actions">
        <button
          type="button"
          className="header__theme-toggle"
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          onClick={toggleTheme}
        >
          {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
        </button>
        <div className="header__user">
          <span className="header__user-info">
            {user.username} · {user.role}
          </span>
          <button type="button" className="header__logout" onClick={onLogout}>
            <LogOut size={12} aria-hidden="true" />
            Sign out
          </button>
        </div>
      </div>
    </header>
  );
}
