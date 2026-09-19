import { CheckCircle2, HelpCircle, ShieldAlert } from "lucide-react";
import type { HashEntry } from "../api";
import type { Verdict } from "../types";
import { Badge } from "./Badge";
import "./StatStrip.css";

/**
 * Pure presentation over data the caller already fetched (verdicts, hashes,
 * chain-verify result) — no fetching here. `chainIntact` is owned by
 * whichever component calls the /api/audit/verify endpoint (Task 9/11).
 */
export function StatStrip({
  verdicts,
  hashes,
  chainIntact,
}: {
  verdicts: Verdict[];
  hashes: HashEntry[];
  chainIntact: boolean | null;
}) {
  const samplesAnalyzed = verdicts.filter((v) => v.sample_hash).length;
  const compromised = verdicts.filter((v) => v.verdict === "Compromised").length;
  const pendingApprovals = hashes.filter((h) => h.status === "pending").length;

  return (
    <div className="stat-strip">
      <div className="stat-strip__item">
        <span className="stat-strip__label">Samples analyzed</span>
        <span className="stat-strip__value">{samplesAnalyzed}</span>
      </div>
      <div className="stat-strip__item">
        <span className="stat-strip__label">Compromised</span>
        <span className="stat-strip__value" data-tone={compromised > 0 ? "compromised" : undefined}>
          {compromised}
        </span>
      </div>
      <div className="stat-strip__item">
        <span className="stat-strip__label">Pending approvals</span>
        <span className="stat-strip__value" data-tone={pendingApprovals > 0 ? "suspicious" : undefined}>
          {pendingApprovals}
        </span>
      </div>
      <div className="stat-strip__item">
        <span className="stat-strip__label">Chain status</span>
        {chainIntact === null ? (
          <Badge tone="inconclusive" icon={<HelpCircle size={12} />}>
            Checking…
          </Badge>
        ) : chainIntact ? (
          <Badge tone="normal" icon={<CheckCircle2 size={12} />}>
            Intact
          </Badge>
        ) : (
          <Badge tone="compromised" icon={<ShieldAlert size={12} />}>
            Broken
          </Badge>
        )}
      </div>
    </div>
  );
}
