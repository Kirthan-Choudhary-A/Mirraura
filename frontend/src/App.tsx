import { useEffect, useState } from "react";
import { applyLiveEvent, applyMonitorEvent, connectLive, fetchMonitorStatus, logout, me, shouldUpdateSampleVerdict } from "./api";
import type { ConnectionState } from "./api";
import { AuditLogTable } from "./components/AuditLogTable";
import { EventFeed } from "./components/EventFeed";
import { LoginPage } from "./components/LoginPage";
import { MonitorBanner } from "./components/MonitorBanner";
import { PendingHashApprovals } from "./components/PendingHashApprovals";
import { UploadPanel } from "./components/UploadPanel";
import { VerdictPanel } from "./components/VerdictPanel";
import type { MirraEvent, Verdict } from "./types";

function App() {
  const [user, setUser] = useState<{ username: string; role: string } | null | undefined>(undefined);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [sampleEvents, setSampleEvents] = useState<MirraEvent[]>([]);
  const [monitorEvents, setMonitorEvents] = useState<MirraEvent[]>([]);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [isolated, setIsolated] = useState(false);
  const [connState, setConnState] = useState<ConnectionState>("connecting");
  const [monitorError, setMonitorError] = useState<string | null>(null);

  useEffect(() => {
    me()
      .then(setUser)
      .catch(() => setUser(null));
  }, []);

  useEffect(() => {
    if (!user) return;
    fetchMonitorStatus()
      .then((s) => {
        setIsolated(s.isolated);
        setMonitorError(null);
      })
      .catch((e) => setMonitorError(e instanceof Error ? e.message : "failed to load monitor status"));
    const conn = connectLive((msg) => {
      setSampleEvents((prev) => applyLiveEvent(prev, msg));
      setMonitorEvents((prev) => applyMonitorEvent(prev, msg));
      if (shouldUpdateSampleVerdict(msg)) {
        setVerdict(msg.data);
      }
      if (msg.type === "verdict") setRefreshKey((k) => k + 1);
      if (msg.type === "isolated") setIsolated(true);
      if (msg.type === "reconnected") setIsolated(false);
    }, setConnState);
    return () => conn.close();
  }, [user]);

  function handleUpload(v: Verdict) {
    setVerdict(v);
    setRefreshKey((k) => k + 1);
  }

  async function handleLogout() {
    await logout().catch(() => {});
    setUser(null);
  }

  if (user === undefined) {
    return null;
  }

  if (user === null) {
    return (
      <>
        {sessionExpired && <p className="error-text">Your session expired. Please sign in again.</p>}
        <LoginPage
          onLogin={(u) => {
            setSessionExpired(false);
            setUser(u);
          }}
        />
      </>
    );
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1 className="app-header__title">Mirraura</h1>
        <p className="app-header__subtitle">
          Shadow honeypot — live behavioral verdict engine
        </p>
        <p className="app-header__conn-state" data-state={connState}>
          {connState === "live" ? "● Live" : connState === "connecting" ? "○ Connecting…" : "○ Offline — retrying"}
        </p>
        <p className="app-header__user">
          {user.username} · {user.role}{" "}
          <button className="app-header__logout" onClick={handleLogout}>
            Sign out
          </button>
        </p>
      </header>

      {monitorError && <p className="error-text">{monitorError}</p>}

      <section className="detonation-zone">
        <div className="detonation-zone__left">
          <UploadPanel
            onVerdict={handleUpload}
            onUploadStart={() => setSampleEvents([])}
            onSessionExpired={() => {
              setSessionExpired(true);
              setUser(null);
            }}
          />
          <VerdictPanel verdict={verdict} />
        </div>
        <div className="detonation-zone__right">
          <EventFeed sampleEvents={sampleEvents} monitorEvents={monitorEvents} />
        </div>
      </section>

      <MonitorBanner isolated={isolated} onReconnected={() => setIsolated(false)} />

      <section className="admin-zone">
        <PendingHashApprovals
          refreshKey={refreshKey}
          role={user.role === "admin" ? "admin" : "analyst"}
          onDecision={() => setRefreshKey((k) => k + 1)}
        />
        <AuditLogTable refreshKey={refreshKey} />
      </section>
    </div>
  );
}

export default App;
