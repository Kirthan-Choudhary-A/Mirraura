import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowDownNarrowWide,
  ArrowUpNarrowWide,
  CheckCircle2,
  Download,
  HelpCircle,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { ApiError, fetchChainStatus, fetchVerdicts } from "../api";
import type { ChainStatus } from "../api";
import type { Verdict } from "../types";
import { Badge } from "./Badge";
import type { BadgeTone } from "./Badge";
import { Card } from "./Card";
import { CopyHash } from "./CopyHash";
import { Skeleton } from "./Skeleton";
import { useToast } from "./Toast";
import "./AuditLogTable.css";

type AuditRow = Verdict & {
  action?: string;
  device_id?: string;
  record_id?: string;
  hash?: string;
  actor?: string;
};

const VERDICT_TONE: Record<Verdict["verdict"], BadgeTone> = {
  Normal: "normal",
  Suspicious: "suspicious",
  Compromised: "compromised",
  Inconclusive: "inconclusive",
};

const VERDICT_ICON: Record<Verdict["verdict"], typeof CheckCircle2> = {
  Normal: CheckCircle2,
  Suspicious: AlertTriangle,
  Compromised: ShieldAlert,
  Inconclusive: HelpCircle,
};

const PAGE_SIZE = 25;

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const RELATIVE_UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31536000],
  ["month", 2592000],
  ["day", 86400],
  ["hour", 3600],
  ["minute", 60],
];

// A historical log's rows are minutes-to-months old by the time anyone
// reads them, so "3h ago" is more useful at a glance than a live-updating
// timestamp — unlike EventFeed's shadow-run trace, which is watched while
// it happens and needs millisecond precision instead.
function relativeTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const seconds = (d.getTime() - Date.now()) / 1000;
  for (const [unit, secondsInUnit] of RELATIVE_UNITS) {
    if (Math.abs(seconds) >= secondsInUnit) {
      return rtf.format(Math.round(seconds / secondsInUnit), unit);
    }
  }
  return rtf.format(Math.round(seconds), "second");
}

// How a row's source value reads in the table -- "interceptor" (the
// internal source string detonateAndScore is called with for an
// auto-intercepted download) gets the label the user actually asked to
// see this by; "sample" (manual dashboard upload) and "monitor"
// (continuous-monitoring batch) get theirs too. Falls back to the raw
// value for anything unrecognized, same convention as DetectionsOverview.
const SOURCE_LABEL: Record<string, string> = {
  sample: "Manual upload",
  interceptor: "Auto-intercepted download",
  monitor: "Continuous monitoring",
};

function matchesQuery(row: AuditRow, query: string): boolean {
  const q = query.toLowerCase();
  const haystack = [row.action, row.verdict, row.actor, row.sample_hash, row.hash, row.source]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(q);
}

function triggerDownload(content: string, mime: string, filename: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Downloads the full (unfiltered, unpaginated) audit log, client-side --
// the data's already in memory from the normal fetch, no new endpoint
// needed either way.
function downloadAuditLogJson(rows: AuditRow[]) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  triggerDownload(JSON.stringify(rows, null, 2), "application/json", `mirraura-audit-log-${stamp}.json`);
}

const CSV_COLUMNS: (keyof AuditRow)[] = [
  "timestamp",
  "sample_filename",
  "sample_hash",
  "hash",
  "source",
  "verdict",
  "action",
  "actor",
  "confidence",
];

function csvCell(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function downloadAuditLogCsv(rows: AuditRow[]) {
  const lines = [CSV_COLUMNS.join(",")];
  for (const r of rows) {
    lines.push(CSV_COLUMNS.map((c) => csvCell(r[c])).join(","));
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  triggerDownload(lines.join("\n"), "text/csv", `mirraura-audit-log-${stamp}.csv`);
}

function ChainIndicator({ status, checkedAt }: { status: ChainStatus | null; checkedAt: Date | null }) {
  if (!status) return null;
  const when = checkedAt ? relativeTime(checkedAt.toISOString()) : null;
  if (status.intact) {
    return (
      <p className="chain-indicator" data-intact="true">
        <ShieldCheck size={16} aria-hidden="true" />
        Chain intact · {status.entries} entries
        {when && <span className="chain-indicator__checked"> · verified {when}</span>}
      </p>
    );
  }
  return (
    <p className="chain-indicator" data-intact="false">
      <ShieldX size={16} aria-hidden="true" />
      Chain broken at entry {status.broken_at}
      {when && <span className="chain-indicator__checked"> · checked {when}</span>}
    </p>
  );
}

export function AuditLogTable({
  refreshKey,
  role,
  onSessionExpired,
  onVerdictsChange,
  onChainStatusChange,
}: {
  refreshKey: number;
  role?: "admin" | "analyst";
  onSessionExpired?: () => void;
  onVerdictsChange?: (v: Verdict[]) => void;
  onChainStatusChange?: (s: ChainStatus | null) => void;
}) {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [chainStatus, setChainStatus] = useState<ChainStatus | null>(null);
  const [chainCheckedAt, setChainCheckedAt] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [sortOrder, setSortOrder] = useState<"newest" | "oldest">("newest");
  const { push } = useToast();

  useEffect(() => {
    let cancelled = false;

    function load() {
      fetchVerdicts()
        .then((v) => {
          if (cancelled) return;
          setRows(v as AuditRow[]);
          onVerdictsChange?.(v);
          setError(null);
        })
        .catch((e) => {
          if (cancelled) return;
          if (e instanceof ApiError && e.status === 401) return onSessionExpired?.();
          if (e instanceof ApiError && e.status === 403) return push("Admins only", "error");
          setError(e instanceof Error ? e.message : "failed to load audit log");
        })
        .finally(() => !cancelled && setLoading(false));
      fetchChainStatus()
        .then((s) => {
          if (cancelled) return;
          setChainStatus(s);
          setChainCheckedAt(new Date());
          onChainStatusChange?.(s);
        })
        .catch(() => {
          if (cancelled) return;
          setChainStatus(null);
          setChainCheckedAt(null);
          onChainStatusChange?.(null);
        });
    }

    load();
    // The WebSocket-driven refreshKey bump (App.tsx, on every "verdict"
    // message) is the primary trigger, but a short poll underneath it means
    // a new entry (e.g. from the auto-interceptor, a separate OS process
    // the browser has no direct line to) shows up within a few seconds
    // even if a WS message is ever missed, instead of needing a full
    // logout/login to force a refetch.
    const interval = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    const base = query.trim() ? rows.filter((r) => matchesQuery(r, query.trim())) : rows;
    // rows arrive oldest-first from the backend (ORDER BY id); reverse for
    // the newest-first default, a plain copy for oldest-first.
    return sortOrder === "newest" ? [...base].reverse() : base;
  }, [rows, query, sortOrder]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const pageRows = filtered.slice(currentPage * PAGE_SIZE, currentPage * PAGE_SIZE + PAGE_SIZE);

  function handleQueryChange(value: string) {
    setQuery(value);
    setPage(0);
  }

  function toggleSortOrder() {
    setSortOrder((o) => (o === "newest" ? "oldest" : "newest"));
    setPage(0);
  }

  return (
    <Card title="Audit log">
      <ChainIndicator status={chainStatus} checkedAt={chainCheckedAt} />
      {error && <p className="error-text">{error}</p>}

      <div className="audit-controls">
        <input
          type="search"
          className="audit-search"
          placeholder="Search hash, verdict, or actor…"
          value={query}
          onChange={(e) => handleQueryChange(e.target.value)}
          aria-label="Search audit log"
        />
        <button type="button" className="audit-sort" onClick={toggleSortOrder}>
          {sortOrder === "newest" ? (
            <ArrowDownNarrowWide size={14} aria-hidden="true" />
          ) : (
            <ArrowUpNarrowWide size={14} aria-hidden="true" />
          )}
          {sortOrder === "newest" ? "Newest first" : "Oldest first"}
        </button>
        <span className="audit-count mono">{filtered.length} entries</span>
        {role === "admin" && rows.length > 0 && (
          <span className="audit-download-group">
            <button type="button" className="audit-download" onClick={() => downloadAuditLogJson(rows)}>
              <Download size={14} aria-hidden="true" />
              JSON
            </button>
            <button type="button" className="audit-download" onClick={() => downloadAuditLogCsv(rows)}>
              <Download size={14} aria-hidden="true" />
              CSV
            </button>
          </span>
        )}
      </div>

      {loading ? (
        <Skeleton rows={5} />
      ) : pageRows.length === 0 ? (
        <p className="empty-copy">No audit entries yet.</p>
      ) : (
        <div className="table-scroll">
          <table className="audit-table">
            <thead>
              <tr>
                <th>When</th>
                <th>File</th>
                <th>Hash</th>
                <th>Source</th>
                <th>Verdict / Action</th>
                <th>Actor</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {pageRows.map((r) => {
                const key = r.verdict_id ?? r.record_id ?? `${r.action}-${r.device_id}-${r.timestamp}`;
                const isVerdict = !r.action;
                const Icon = isVerdict ? VERDICT_ICON[r.verdict] : null;
                const hash = isVerdict ? r.sample_hash : r.hash;
                return (
                  <tr key={key}>
                    <td className="mono" title={r.timestamp}>
                      {relativeTime(r.timestamp)}
                    </td>
                    <td className="mono">{isVerdict ? r.sample_filename || "—" : "—"}</td>
                    <td>{hash ? <CopyHash hash={hash} /> : "—"}</td>
                    <td>{isVerdict ? SOURCE_LABEL[r.source] ?? r.source : "—"}</td>
                    <td>
                      {isVerdict && Icon ? (
                        <Badge tone={VERDICT_TONE[r.verdict]} icon={<Icon size={14} />}>
                          {r.verdict}
                        </Badge>
                      ) : (
                        <Badge tone="neutral" icon={<HelpCircle size={14} />}>
                          {r.action ?? "—"}
                        </Badge>
                      )}
                    </td>
                    <td className="mono">{r.actor || "—"}</td>
                    <td className="mono">{isVerdict ? r.confidence.toFixed(2) : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {pageCount > 1 && (
        <div className="audit-pagination">
          <button type="button" disabled={currentPage === 0} onClick={() => setPage((p) => p - 1)}>
            Previous
          </button>
          <span className="mono">
            Page {currentPage + 1} of {pageCount}
          </span>
          <button type="button" disabled={currentPage >= pageCount - 1} onClick={() => setPage((p) => p + 1)}>
            Next
          </button>
        </div>
      )}
    </Card>
  );
}
