import type { ReactNode } from "react";
import "./Badge.css";

export type BadgeTone = "normal" | "suspicious" | "compromised" | "inconclusive" | "neutral";

/**
 * Small icon+text pill. Tone drives color via the --sev-* tokens; "neutral"
 * uses --border/--text-muted for non-verdict badges (e.g. counts).
 *
 * Icon is a required prop (never color alone) — callers pass a lucide-react
 * icon. Recommended pairing for the four verdict tones, kept consistent
 * everywhere Badge is used: normal -> CheckCircle2, suspicious ->
 * AlertTriangle, compromised -> ShieldAlert, inconclusive -> HelpCircle.
 */
export function Badge({ tone, icon, children }: { tone: BadgeTone; icon: ReactNode; children: ReactNode }) {
  return (
    <span className="badge" data-tone={tone}>
      <span className="badge__icon" aria-hidden="true">
        {icon}
      </span>
      <span className="badge__text">{children}</span>
    </span>
  );
}
