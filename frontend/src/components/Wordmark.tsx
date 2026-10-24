import "./Wordmark.css";

/**
 * Shared wordmark for Header and LoginPage: two overlapping, offset rounded
 * squares — a solid `--text` shape in front, `--accent` at reduced opacity
 * behind and offset — reading as a duplicated "shadow" silhouette (the
 * shadow-honeypot sitting just behind every real detonation). Both fills
 * are CSS custom properties so the mark self-adapts across themes; the
 * static favicon (which can't see page CSS vars) uses literal colors that
 * approximate the dark-theme rendering.
 */
export function Wordmark({
  size = 20,
  withText = true,
  className,
}: {
  size?: number;
  withText?: boolean;
  className?: string;
}) {
  return (
    <span className={className ? `wordmark ${className}` : "wordmark"}>
      <svg className="wordmark__mark" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
        <rect x="11" y="11" width="17" height="17" rx="6" fill="var(--accent)" opacity="0.45" />
        <rect x="4" y="4" width="17" height="17" rx="6" fill="var(--text)" />
      </svg>
      {withText && <span className="wordmark__text">Mirraura</span>}
    </span>
  );
}
