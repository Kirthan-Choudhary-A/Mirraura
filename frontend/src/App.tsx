import { useEffect, useState } from "react";
import { connectLive, fetchMonitorStatus } from "./api";
import { AuditLogTable } from "./components/AuditLogTable";
import { EventFeed } from "./components/EventFeed";
import { MonitorBanner } from "./components/MonitorBanner";
import { UploadPanel } from "./components/UploadPanel";
import { VerdictPanel } from "./components/VerdictPanel";
import type { MirraEvent, Verdict } from "./types";

function App() {
  const [events, setEvents] = useState<MirraEvent[]>([]);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [isolated, setIsolated] = useState(false);

  useEffect(() => {
    fetchMonitorStatus()
      .then((s) => setIsolated(s.isolated))
      .catch(() => {});
    const ws = connectLive((msg) => {
      if (msg.type === "event") setEvents((prev) => [...prev, msg.data]);
      if (msg.type === "verdict") setVerdict(msg.data);
      if (msg.type === "isolated") setIsolated(true);
      if (msg.type === "reconnected") setIsolated(false);
    });
    return () => ws.close();
  }, []);

  function handleUpload(v: Verdict) {
    setVerdict(v);
    setRefreshKey((k) => k + 1);
  }

  function handleNewRun() {
    setEvents([]);
  }

  return (
    <div>
      <h1>Mirraura</h1>
      <MonitorBanner isolated={isolated} onReconnected={() => setIsolated(false)} />
      <div onClickCapture={handleNewRun}>
        <UploadPanel onVerdict={handleUpload} />
      </div>
      <EventFeed events={events} />
      <VerdictPanel verdict={verdict} />
      <AuditLogTable refreshKey={refreshKey} />
    </div>
  );
}

export default App;
