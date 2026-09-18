import type { MirraEvent, Verdict } from "./types";

export type HashEntry = {
  hash: string;
  label: string;
  status: "pending" | "approved" | "rejected";
  source: "auto" | "manual";
  proposed_at: string;
  reviewed_at: string | null;
};

const BASE = import.meta.env.VITE_BACKEND_URL || "http://localhost:8080";

export async function uploadSample(file: File): Promise<Verdict> {
  const form = new FormData();
  form.append("sample", file);
  const res = await fetch(`${BASE}/api/samples`, { method: "POST", body: form });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function fetchVerdicts(): Promise<Verdict[]> {
  const res = await fetch(`${BASE}/api/verdicts`);
  return res.json();
}

export async function fetchMonitorStatus(): Promise<{ isolated: boolean }> {
  const res = await fetch(`${BASE}/api/monitor/status`);
  return res.json();
}

export async function reconnectMonitor(): Promise<void> {
  const res = await fetch(`${BASE}/api/monitor/reconnect`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
}

export async function fetchHashes(): Promise<HashEntry[]> {
  const res = await fetch(`${BASE}/api/hashes`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function submitHash(hash: string, label: string): Promise<void> {
  const res = await fetch(`${BASE}/api/hashes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hash, label }),
  });
  if (!res.ok) throw new Error(await res.text());
}

export async function approveHash(hash: string): Promise<void> {
  const res = await fetch(`${BASE}/api/hashes/${hash}/approve`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
}

export async function rejectHash(hash: string): Promise<void> {
  const res = await fetch(`${BASE}/api/hashes/${hash}/reject`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
}

export type LiveMessage =
  | { type: "event"; source: "sample" | "monitor"; data: MirraEvent }
  | { type: "verdict"; source: "sample" | "monitor"; data: Verdict }
  | { type: "isolated" }
  | { type: "reconnected" };

const MAX_EVENTS = 500;

// Only the shadow-run feed is rendered today (App.tsx); monitor-loop events
// are received but not yet shown anywhere (Part 3 adds that tab), so they're
// filtered out here rather than mixed into the same list.
export function applyLiveEvent(events: MirraEvent[], msg: LiveMessage): MirraEvent[] {
  if (msg.type !== "event" || msg.source !== "sample") return events;
  return [...events, msg.data].slice(-MAX_EVENTS);
}

export function shouldUpdateSampleVerdict(
  msg: LiveMessage
): msg is Extract<LiveMessage, { type: "verdict" }> {
  return msg.type === "verdict" && msg.source === "sample";
}

export function connectLive(onMessage: (msg: LiveMessage) => void): WebSocket {
  const wsUrl = BASE.replace(/^http/, "ws") + "/api/live";
  const ws = new WebSocket(wsUrl);
  ws.onmessage = (ev) => onMessage(JSON.parse(ev.data));
  return ws;
}
