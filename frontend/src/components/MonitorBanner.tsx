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

  if (!isolated) return null;

  async function handleReconnect() {
    setBusy(true);
    try {
      await reconnectMonitor();
      onReconnected();
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
    </div>
  );
}
