import { useEffect, useState } from "react";
import { applyLiveEvent, connectLive, fetchMonitorStatus, shouldUpdateSampleVerdict } from "./api";
import type { ConnectionState } from "./api";
import { AuditLogTable } from "./components/AuditLogTable";
import { EventFeed } from "./components/EventFeed";
import { MonitorBanner } from "./components/MonitorBanner";
import { PendingHashApprovals } from "./components/PendingHashApprovals";
import { UploadPanel } from "./components/UploadPanel";
import { VerdictPanel } from "./components/VerdictPanel";
import type { MirraEvent, Verdict } from "./types";

function App() {
  const [events, setEvents] = useState<MirraEvent[]>([]);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [isolated, setIsolated] = useState(false);
  const [connState, setConnState] = useState<ConnectionState>("connecting");

  useEffect(() => {
    fetchMonitorStatus()
      .then((s) => setIsolated(s.isolated))
      .catch(() => {});
    const conn = connectLive((msg) => {
      setEvents((prev) => applyLiveEvent(prev, msg));
      if (shouldUpdateSampleVerdict(msg)) {
        setVerdict(msg.data);
      }
      if (msg.type === "verdict") setRefreshKey((k) => k + 1);
      if (msg.type === "isolated") setIsolated(true);
      if (msg.type === "reconnected") setIsolated(false);
    }, setConnState);
    return () => conn.close();
  }, []);

  function handleUpload(v: Verdict) {
    setVerdict(v);
    setRefreshKey((k) => k + 1);
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
      </header>

      <section className="detonation-zone">
        <div className="detonation-zone__left">
          <UploadPanel onVerdict={handleUpload} onUploadStart={() => setEvents([])} />
          <VerdictPanel verdict={verdict} />
        </div>
        <div className="detonation-zone__right">
          <EventFeed events={events} />
        </div>
      </section>

      <MonitorBanner isolated={isolated} onReconnected={() => setIsolated(false)} />

      <section className="admin-zone">
        <PendingHashApprovals
          refreshKey={refreshKey}
          onDecision={() => setRefreshKey((k) => k + 1)}
        />
        <AuditLogTable refreshKey={refreshKey} />
      </section>
    </div>
  );
}

export default App;
