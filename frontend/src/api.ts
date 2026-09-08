import type { MirraEvent, Verdict } from "./types";

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

export type LiveMessage =
  | { type: "event"; data: MirraEvent }
  | { type: "verdict"; data: Verdict }
  | { type: "isolated" }
  | { type: "reconnected" };

export function connectLive(onMessage: (msg: LiveMessage) => void): WebSocket {
  const wsUrl = BASE.replace(/^http/, "ws") + "/api/live";
  const ws = new WebSocket(wsUrl);
  ws.onmessage = (ev) => onMessage(JSON.parse(ev.data));
  return ws;
}
