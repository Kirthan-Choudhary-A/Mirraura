import { useState } from "react";
import { reconnectMonitor } from "../api";

export function MonitorBanner({
  isolated,
  onReconnected,
}: {
  isolated: boolean;
  onReconnected: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isolated) return null;

  async function handleReconnect() {
    setBusy(true);
    setError(null);
    try {
      await reconnectMonitor();
      onReconnected();
    } catch (e) {
      setError(e instanceof Error ? e.message : "reconnect failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="monitor-banner">
      <span>Monitored endpoint isolated — network disconnected after a Compromised verdict.</span>
      <button className="monitor-banner__button" onClick={handleReconnect} disabled={busy}>
        {busy ? "Reconnecting…" : "Reconnect"}
      </button>
      {error && <span className="monitor-banner__error">{error}</span>}
    </div>
  );
}
