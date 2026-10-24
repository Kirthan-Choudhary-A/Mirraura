import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { useToast } from "./Toast";
import "./CopyHash.css";

/** Truncates `s` to its first/last `keep` characters, joined by an ellipsis. */
export function truncateMiddle(s: string, keep: number = 6): string {
  if (s.length <= keep * 2) return s;
  return `${s.slice(0, keep)}…${s.slice(-keep)}`;
}

/**
 * Click-to-copy hash display. The full hash is available on hover via
 * `title`, and to screen readers via a visually-hidden element (not `title`
 * alone, which assistive tech doesn't reliably read).
 */
export function CopyHash({ hash, label }: { hash: string; label?: string }) {
  const { push } = useToast();
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      push("Copied to clipboard", "success");
      setTimeout(() => setCopied(false), 1500);
    } catch {
      push("Copy failed", "error");
    }
  }

  return (
    <button type="button" className="copy-hash mono" onClick={handleCopy} title={hash}>
      <span aria-hidden="true">{truncateMiddle(hash)}</span>
      <span className="copy-hash__sr-only">
        {label ? `${label}: ` : ""}
        {hash} — click to copy
      </span>
      {copied ? <Check className="copy-hash__icon" aria-hidden="true" size={12} /> : <Copy className="copy-hash__icon" aria-hidden="true" size={12} />}
    </button>
  );
}
