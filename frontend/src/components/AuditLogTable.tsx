import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, HelpCircle, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { fetchChainStatus, fetchVerdicts } from "../api";
import type { ChainStatus } from "../api";
import type { Verdict } from "../types";
import { Badge } from "./Badge";
import type { BadgeTone } from "./Badge";
import { Card } from "./Card";
import { CopyHash } from "./CopyHash";
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

function matchesQuery(row: AuditRow, query: string): boolean {
  const q = query.toLowerCase();
  const haystack = [row.action, row.verdict, row.actor, row.sample_hash, row.hash]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(q);
}

function ChainIndicator({ status }: { status: ChainStatus | null }) {
  if (!status) return null;
  if (status.intact) {
    return (
      <p className="chain-indicator" data-intact="true">
        <ShieldCheck size={16} aria-hidden="true" />
        Chain intact · {status.entries} entries
      </p>
    );
  }
  return (
    <p className="chain-indicator" data-intact="false">
      <ShieldX size={16} aria-hidden="true" />
      Chain broken at entry {status.broken_at}
    </p>
  );
}

export function AuditLogTable({ refreshKey }: { refreshKey: number }) {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [chainStatus, setChainStatus] = useState<ChainStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);

  useEffect(() => {
    fetchVerdicts()
      .then((v) => {
        setRows(v as AuditRow[]);
        setError(null);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load audit log"));
    fetchChainStatus()
      .then(setChainStatus)
      .catch(() => setChainStatus(null));
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!query.trim()) return rows;
    return rows.filter((r) => matchesQuery(r, query.trim()));
  }, [rows, query]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const pageRows = filtered.slice(currentPage * PAGE_SIZE, currentPage * PAGE_SIZE + PAGE_SIZE);

  function handleQueryChange(value: string) {
    setQuery(value);
    setPage(0);
  }

  return (
    <Card title="Audit log">
      <ChainIndicator status={chainStatus} />
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
        <span className="audit-count mono">{filtered.length} entries</span>
      </div>

      {pageRows.length === 0 ? (
        <p className="empty-copy">No audit entries yet.</p>
      ) : (
        <div className="table-scroll">
          <table className="audit-table">
            <thead>
              <tr>
                <th>When</th>
                <th>File</th>
                <th>Hash</th>
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
