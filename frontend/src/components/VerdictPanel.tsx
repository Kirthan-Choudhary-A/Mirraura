import type { Verdict } from "../types";

const VERDICT_COLOR: Record<Verdict["verdict"], string> = {
  Normal: "green",
  Suspicious: "orange",
  Compromised: "red",
  Inconclusive: "gray",
};

export function VerdictPanel({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) return <p>No verdict yet — upload a sample.</p>;
  return (
    <div>
      <h2 style={{ color: VERDICT_COLOR[verdict.verdict] }}>
        {verdict.verdict} ({(verdict.confidence * 100).toFixed(0)}% confidence)
      </h2>
      <h3>Causal chain</h3>
      <ol>
        {verdict.causal_chain.map((reason, i) => (
          <li key={i}>{reason}</li>
        ))}
      </ol>
    </div>
  );
}
