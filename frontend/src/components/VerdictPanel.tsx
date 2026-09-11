import type { Verdict } from "../types";

const VERDICT_COLOR: Record<Verdict["verdict"], string> = {
  Normal: "var(--sev-normal)",
  Suspicious: "var(--sev-suspicious)",
  Compromised: "var(--sev-compromised)",
  Inconclusive: "var(--sev-inconclusive)",
};

export function VerdictPanel({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) {
    return (
      <div className="panel">
        <h2>Verdict</h2>
        <p className="empty-copy">No verdict yet. Upload a sample to see what it does.</p>
      </div>
    );
  }

  return (
    <div className="panel">
      <h2>Verdict</h2>
      <div
        key={verdict.verdict_id}
        className="verdict-flash"
        style={{ "--severity": VERDICT_COLOR[verdict.verdict] } as React.CSSProperties}
      >
        <p className="verdict-readout">{verdict.verdict}</p>
        <p className="verdict-confidence">{(verdict.confidence * 100).toFixed(0)}% confidence</p>
        <h3>Causal chain</h3>
        <ul className="causal-list">
          {verdict.causal_chain.map((reason, i) => (
            <li key={i}>{reason}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
