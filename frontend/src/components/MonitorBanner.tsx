import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import { reconnectMonitor } from "../api";
import { ConfirmDialog } from "./ConfirmDialog";
import "./MonitorBanner.css";

export function MonitorBanner({
  isolated,
  role,
  onReconnected,
}: {
  isolated: boolean;
  role: "admin" | "analyst";
  onReconnected: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  if (!isolated) return null;

  async function handleReconnect() {
    setConfirming(false);
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
    <div className="monitor-banner" role="alert">
      <span className="monitor-banner__dot" aria-hidden="true" />
      <ShieldAlert className="monitor-banner__icon" aria-hidden="true" size={18} />
      <span className="monitor-banner__text">
        Monitored endpoint isolated — network disconnected after a Compromised verdict.
      </span>
      {/* No isolation timestamp is threaded from the backend today (monitor
          status is just { isolated: boolean}) — showing "since <time>" here
          would mean fabricating a value, so it's omitted rather than guessed. */}
      {role === "admin" && (
        <button className="monitor-banner__button" onClick={() => setConfirming(true)} disabled={busy}>
          {busy ? "Reconnecting…" : "Reconnect"}
        </button>
      )}
      {error && <span className="monitor-banner__error">{error}</span>}

      <ConfirmDialog
        open={confirming}
        title="Reconnect the monitored endpoint?"
        description="This restores network access for the isolated device. Only do this once the compromise has been investigated."
        confirmLabel="Reconnect"
        onConfirm={handleReconnect}
        onCancel={() => setConfirming(false)}
      />
    </div>
  );
}
