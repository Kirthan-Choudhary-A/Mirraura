import "./Skeleton.css";

/** Shimmer placeholder shaped like the eventual content, shown while a
 * component's first fetch is in flight. */
export function Skeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="skeleton" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <div className="skeleton__row" key={i} />
      ))}
    </div>
  );
}
