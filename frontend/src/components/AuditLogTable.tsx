import { useEffect, useState } from "react";
import { fetchVerdicts } from "../api";
import type { Verdict } from "../types";

type AuditRow = Verdict & {
  action?: string;
  device_id?: string;
  record_id?: string;
  hash?: string;
};

const SEVERITY_COLOR: Record<Verdict["verdict"], string> = {
  Normal: "var(--sev-normal)",
  Suspicious: "var(--sev-suspicious)",
  Compromised: "var(--sev-compromised)",
  Inconclusive: "var(--sev-inconclusive)",
};

export function AuditLogTable({ refreshKey }: { refreshKey: number }) {
  const [verdicts, setVerdicts] = useState<AuditRow[]>([]);

  useEffect(() => {
    fetchVerdicts()
      .then((v) => setVerdicts(v as AuditRow[]))
      .catch(() => setVerdicts([]));
  }, [refreshKey]);

  return (
    <div className="panel">
      <h2>Audit Log</h2>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Sample Hash / Device</th>
              <th>Verdict / Action</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {verdicts.map((v) => {
              const key = v.verdict_id ?? v.record_id ?? `${v.action}-${v.device_id}`;
              const isVerdict = !v.action;
              const color = isVerdict ? SEVERITY_COLOR[v.verdict] : null;
              return (
                <tr key={key}>
                  <td className="mono">{v.timestamp}</td>
                  <td className="mono">
                    {v.action
                      ? v.device_id
                        ? `device: ${v.device_id}`
                        : v.hash
                          ? `hash: ${v.hash.slice(0, 12)}...`
                          : "—"
                      : `${v.sample_hash.slice(0, 12)}...`}
                  </td>
                  <td className="label-cell">
                    <span className="verdict-cell">
                      {color && (
                        <span className="severity-dot" style={{ background: color }} />
                      )}
                      {v.action ?? v.verdict}
                    </span>
                  </td>
                  <td className="mono">{v.action ? "—" : v.confidence.toFixed(2)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
