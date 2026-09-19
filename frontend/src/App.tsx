import { useEffect, useState } from "react";
import {
  applyLiveEvent,
  applyMonitorEvent,
  connectLive,
  fetchMonitorStatus,
  logout,
  me,
  shouldUpdateSampleVerdict,
} from "./api";
import type { ChainStatus, ConnectionState, HashEntry } from "./api";
import { AuditLogTable } from "./components/AuditLogTable";
import { EventFeed } from "./components/EventFeed";
import { Header } from "./components/Header";
import { LoginPage } from "./components/LoginPage";
import { MonitorBanner } from "./components/MonitorBanner";
import { PendingHashApprovals } from "./components/PendingHashApprovals";
import { Skeleton } from "./components/Skeleton";
import { StatStrip } from "./components/StatStrip";
import { TabPanel, Tabs } from "./components/Tabs";
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
  const [bottomTab, setBottomTab] = useState<"audit" | "hashes">("audit");
  const [liveAnnouncement, setLiveAnnouncement] = useState("");

  // StatStrip's source data — owned by AuditLogTable/PendingHashApprovals
  // (they already fetch it for their own tables) and lifted here via
  // callbacks so the chain-status/verdicts/hashes endpoints are each hit
  // from exactly one place.
  const [verdicts, setVerdicts] = useState<Verdict[] | null>(null);
  const [hashes, setHashes] = useState<HashEntry[] | null>(null);
  const [chainStatus, setChainStatus] = useState<ChainStatus | null>(null);

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
        setLiveAnnouncement(`New verdict: ${msg.data.verdict} for ${msg.data.sample_filename}`);
      }
      if (msg.type === "verdict") setRefreshKey((k) => k + 1);
      if (msg.type === "isolated") {
        setIsolated(true);
        setLiveAnnouncement("Monitored endpoint isolated after a compromised verdict.");
      }
      if (msg.type === "reconnected") {
        setIsolated(false);
        setLiveAnnouncement("Monitored endpoint reconnected.");
      }
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

  function handleSessionExpired() {
    setSessionExpired(true);
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

  const role: "admin" | "analyst" = user.role === "admin" ? "admin" : "analyst";
  const pendingCount = hashes?.filter((h) => h.status === "pending").length ?? 0;

  return (
    <div className="app">
      <span className="sr-only" aria-live="polite">
        {liveAnnouncement}
      </span>

      <Header user={user} connState={connState} monitorIsolated={isolated} onLogout={handleLogout} />

      {monitorError && <p className="error-text">{monitorError}</p>}

      {verdicts && hashes ? (
        <StatStrip verdicts={verdicts} hashes={hashes} chainIntact={chainStatus?.intact ?? null} />
      ) : (
        <Skeleton rows={1} />
      )}

      <MonitorBanner isolated={isolated} role={role} onReconnected={() => setIsolated(false)} />

      <section className="detonation-zone">
        <div className="detonation-zone__left">
          <UploadPanel
            onVerdict={handleUpload}
            onUploadStart={() => setSampleEvents([])}
            onSessionExpired={handleSessionExpired}
          />
          <VerdictPanel verdict={verdict} />
        </div>
        <div className="detonation-zone__right">
          <EventFeed sampleEvents={sampleEvents} monitorEvents={monitorEvents} />
        </div>
      </section>

      <section className="log-zone">
        <Tabs
          tabs={[
            { id: "audit", label: "Audit log" },
            {
              id: "hashes",
              label: "Hash approvals",
              badge: pendingCount > 0 ? <span className="tabs__badge">{pendingCount}</span> : undefined,
            },
          ]}
          active={bottomTab}
          onChange={(id) => setBottomTab(id as "audit" | "hashes")}
        />
        <TabPanel id="audit" active={bottomTab}>
          <AuditLogTable
            refreshKey={refreshKey}
            onSessionExpired={handleSessionExpired}
            onVerdictsChange={setVerdicts}
            onChainStatusChange={setChainStatus}
          />
        </TabPanel>
        <TabPanel id="hashes" active={bottomTab}>
          <PendingHashApprovals
            refreshKey={refreshKey}
            role={role}
            onDecision={() => setRefreshKey((k) => k + 1)}
            onSessionExpired={handleSessionExpired}
            onHashesChange={setHashes}
          />
        </TabPanel>
      </section>
    </div>
  );
}

export default App;
