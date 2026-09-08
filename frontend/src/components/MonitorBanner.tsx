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
    <div style={{ background: "#5c1a1a", color: "white", padding: "0.75rem 1rem" }}>
      Monitored endpoint isolated — network disconnected after a Compromised verdict.
      <button onClick={handleReconnect} disabled={busy} style={{ marginLeft: "1rem" }}>
        {busy ? "Reconnecting..." : "Reconnect"}
      </button>
      {error && <span style={{ marginLeft: "1rem", color: "#ffb3b3" }}>{error}</span>}
    </div>
  );
}
