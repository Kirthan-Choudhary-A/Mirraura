import type { MirraEvent, Verdict } from "./types";

export type HashEntry = {
  hash: string;
  label: string;
  status: "pending" | "approved" | "rejected";
  source: "auto" | "manual";
  proposed_at: string;
  reviewed_at: string | null;
};

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  if (!res.ok) {
    throw new ApiError(await res.text(), res.status);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json();
}

export async function login(username: string, password: string): Promise<{ username: string; role: string }> {
  return request("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
}

export async function logout(): Promise<void> {
  await request("/api/logout", { method: "POST" });
}

export async function me(): Promise<{ username: string; role: string }> {
  return request("/api/me");
}

export async function uploadSample(file: File): Promise<Verdict> {
  const form = new FormData();
  form.append("sample", file);
  return request("/api/samples", { method: "POST", body: form });
}

/** SHA-256 of a file's bytes, hex-encoded. Computed client-side so the
 * upload panel can show the hash before the file is actually sent. */
export async function sha256Hex(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Matches the backend's known-bad-hash format: 64 lowercase hex chars. */
export function isValidSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

export async function fetchVerdicts(): Promise<Verdict[]> {
  return request("/api/verdicts");
}

export async function fetchMonitorStatus(): Promise<{ isolated: boolean }> {
  return request("/api/monitor/status");
}

export type ChainStatus = { intact: boolean; entries: number; broken_at: number | null };

export async function fetchChainStatus(): Promise<ChainStatus> {
  return request("/api/audit/verify");
}

export async function reconnectMonitor(): Promise<void> {
  await request("/api/monitor/reconnect", { method: "POST" });
}

export async function fetchHashes(): Promise<HashEntry[]> {
  return request("/api/hashes");
}

export async function submitHash(hash: string, label: string): Promise<void> {
  await request("/api/hashes", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hash, label }),
  });
}

export async function approveHash(hash: string): Promise<void> {
  await request(`/api/hashes/${hash}/approve`, { method: "POST" });
}

export async function rejectHash(hash: string): Promise<void> {
  await request(`/api/hashes/${hash}/reject`, { method: "POST" });
}

export type LiveMessage =
  | { type: "event"; source: "sample" | "monitor"; data: MirraEvent }
  | { type: "verdict"; source: "sample" | "monitor"; data: Verdict }
  | { type: "isolated" }
  | { type: "reconnected" };

const MAX_EVENTS = 500;

export function applyLiveEvent(events: MirraEvent[], msg: LiveMessage): MirraEvent[] {
  if (msg.type !== "event" || msg.source !== "sample") return events;
  return [...events, msg.data].slice(-MAX_EVENTS);
}

/** Sibling to applyLiveEvent for the "Endpoint monitor" feed tab. */
export function applyMonitorEvent(events: MirraEvent[], msg: LiveMessage): MirraEvent[] {
  if (msg.type !== "event" || msg.source !== "monitor") return events;
  return [...events, msg.data].slice(-MAX_EVENTS);
}

export function shouldUpdateSampleVerdict(
  msg: LiveMessage
): msg is Extract<LiveMessage, { type: "verdict" }> {
  return msg.type === "verdict" && msg.source === "sample";
}

export type ConnectionState = "connecting" | "live" | "offline";

const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;

export function nextBackoffMs(current: number): number {
  return Math.min(current * 2, MAX_BACKOFF_MS);
}

export function connectLive(
  onMessage: (msg: LiveMessage) => void,
  onStatus: (state: ConnectionState) => void
): { close: () => void } {
  let ws: WebSocket | null = null;
  let closed = false;
  let backoff = INITIAL_BACKOFF_MS;

  function connect() {
    if (closed) return;
    onStatus("connecting");
    const wsUrl = (window.location.protocol === "https:" ? "wss://" : "ws://") + window.location.host + "/api/live";
    ws = new WebSocket(wsUrl);
    ws.onopen = () => {
      backoff = INITIAL_BACKOFF_MS;
      onStatus("live");
    };
    ws.onmessage = (ev) => {
      try {
        onMessage(JSON.parse(ev.data));
      } catch {
        // malformed frame — drop it rather than crash the socket handler
      }
    };
    ws.onclose = () => {
      if (closed) return;
      onStatus("offline");
      const delay = backoff;
      backoff = nextBackoffMs(backoff);
      setTimeout(connect, delay);
    };
    ws.onerror = () => {
      ws?.close();
    };
  }

  connect();

  return {
    close() {
      closed = true;
      ws?.close();
    },
  };
}
