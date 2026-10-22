import type { Verdict } from "../types";
import "./StatStrip.css";

const SOURCE_LABEL: Record<string, string> = {
  sample: "Manual upload",
  interceptor: "Auto-intercepted download",
  monitor: "Continuous monitoring",
};

const METHOD_LABEL: Record<string, string> = {
  known_bad_hash: "Known-bad hash",
  static_triage: "Static triage",
  dynamic: "Detonated & scored",
};

function countBy(verdicts: Verdict[], key: "source" | "detection_method"): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const v of verdicts) {
    counts[v[key]] = (counts[v[key]] ?? 0) + 1;
  }
  return counts;
}

/**
 * Pure presentation over verdicts the caller already fetched -- same shape
 * as StatStrip, no fetching of its own. Breaks verdicts down by how they
 * arrived (source) and how they were judged (detection_method).
 */
export function DetectionsOverview({ verdicts }: { verdicts: Verdict[] }) {
  const bySource = countBy(verdicts, "source");
  const byMethod = countBy(verdicts, "detection_method");

  return (
    <div className="stat-strip" data-testid="detections-overview">
      {Object.entries(bySource).map(([source, count]) => (
        <div className="stat-strip__item" key={`source-${source}`}>
          <span className="stat-strip__label">{SOURCE_LABEL[source] ?? source}</span>
          <span className="stat-strip__value">{count}</span>
        </div>
      ))}
      {Object.entries(byMethod).map(([method, count]) => (
        <div className="stat-strip__item" key={`method-${method}`}>
          <span className="stat-strip__label">{METHOD_LABEL[method] ?? method}</span>
          <span className="stat-strip__value">{count}</span>
        </div>
      ))}
    </div>
  );
}
