import { useEffect, useState } from "react";
import { fetchVerdicts } from "../api";
import type { Verdict } from "../types";

export function AuditLogTable({ refreshKey }: { refreshKey: number }) {
  const [verdicts, setVerdicts] = useState<Verdict[]>([]);

  useEffect(() => {
    fetchVerdicts().then(setVerdicts).catch(() => setVerdicts([]));
  }, [refreshKey]);

  return (
    <div>
      <h2>Audit Log</h2>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Sample Hash</th>
            <th>Verdict</th>
            <th>Confidence</th>
          </tr>
        </thead>
        <tbody>
          {verdicts.map((v) => (
            <tr key={v.verdict_id}>
              <td>{v.timestamp}</td>
              <td>{v.sample_hash.slice(0, 12)}...</td>
              <td>{v.verdict}</td>
              <td>{v.confidence.toFixed(2)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
