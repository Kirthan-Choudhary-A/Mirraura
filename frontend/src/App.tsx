import { useEffect, useState } from "react";
import { connectLive } from "./api";
import { AuditLogTable } from "./components/AuditLogTable";
import { EventFeed } from "./components/EventFeed";
import { UploadPanel } from "./components/UploadPanel";
import { VerdictPanel } from "./components/VerdictPanel";
import type { MirraEvent, Verdict } from "./types";

function App() {
  const [events, setEvents] = useState<MirraEvent[]>([]);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const ws = connectLive((msg) => {
      if (msg.type === "event") setEvents((prev) => [...prev, msg.data]);
      if (msg.type === "verdict") setVerdict(msg.data);
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
