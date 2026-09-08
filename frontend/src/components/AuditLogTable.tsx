import { useEffect, useState } from "react";
import { fetchVerdicts } from "../api";
import type { Verdict } from "../types";

type AuditRow = Verdict & {
  action?: string;
  device_id?: string;
  record_id?: string;
};

export function AuditLogTable({ refreshKey }: { refreshKey: number }) {
  const [verdicts, setVerdicts] = useState<AuditRow[]>([]);

  useEffect(() => {
    fetchVerdicts()
      .then((v) => setVerdicts(v as AuditRow[]))
      .catch(() => setVerdicts([]));
  }, [refreshKey]);

  return (
    <div>
      <h2>Audit Log</h2>
      <table>
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
            return (
              <tr key={key}>
                <td>{v.timestamp}</td>
                <td>{v.action ? `device: ${v.device_id}` : `${v.sample_hash.slice(0, 12)}...`}</td>
                <td>{v.action ?? v.verdict}</td>
                <td>{v.action ? "—" : v.confidence.toFixed(2)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
