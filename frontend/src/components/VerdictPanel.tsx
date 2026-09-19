import { AlertTriangle, CheckCircle2, HelpCircle, ShieldAlert } from "lucide-react";
import type { Verdict } from "../types";
import { Badge } from "./Badge";
import type { BadgeTone } from "./Badge";
import { Card } from "./Card";
import { CopyHash } from "./CopyHash";
import "./VerdictPanel.css";

const TONE: Record<Verdict["verdict"], BadgeTone> = {
  Normal: "normal",
  Suspicious: "suspicious",
  Compromised: "compromised",
  Inconclusive: "inconclusive",
};

const ICON: Record<Verdict["verdict"], typeof CheckCircle2> = {
  Normal: CheckCircle2,
  Suspicious: AlertTriangle,
  Compromised: ShieldAlert,
  Inconclusive: HelpCircle,
};

export function VerdictPanel({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) {
    return (
      <Card title="Verdict">
        <p className="empty-copy">Nothing detonated yet. Upload a sample and its verdict will appear here.</p>
      </Card>
    );
  }

  const tone = TONE[verdict.verdict];
  const Icon = ICON[verdict.verdict];
  const confidencePct = Math.round(verdict.confidence * 100);

  return (
    <Card title="Verdict">
      <div key={verdict.verdict_id} className="verdict-result" data-tone={tone}>
        <Badge tone={tone} icon={<Icon size={16} />}>
          {verdict.verdict}
        </Badge>

        <div className="verdict-confidence">
          <div className="verdict-confidence__bar">
            <div className="verdict-confidence__fill" style={{ width: `${confidencePct}%` }} />
          </div>
          <span className="mono">{confidencePct}% confidence</span>
        </div>

        <dl className="verdict-meta">
          <dt>File</dt>
          <dd className="mono">{verdict.sample_filename || "—"}</dd>
          <dt>SHA-256</dt>
          <dd>
            <CopyHash hash={verdict.sample_hash} label="Sample hash" />
          </dd>
          <dt>Detonated</dt>
          <dd className="mono">{verdict.timestamp}</dd>
        </dl>

        <h3>Causal chain</h3>
        {verdict.causal_chain.length === 0 ? (
          <p className="empty-copy">No suspicious behavior observed.</p>
        ) : (
          <ol className="causal-timeline">
            {verdict.causal_chain.map((reason, i) => (
              <li key={i}>
                <span className="causal-timeline__dot" aria-hidden="true" />
                <span>{reason}</span>
              </li>
            ))}
          </ol>
        )}
      </div>
    </Card>
  );
}
