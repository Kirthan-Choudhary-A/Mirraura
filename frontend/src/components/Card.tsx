import type { ReactNode } from "react";
import "./Card.css";

/**
 * The one panel/card shell every other component renders inside. Replaces
 * the bare `<div className="panel">` pattern used before this task.
 */
export function Card({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <div className="card">
      <div className="card__header">
        <h2 className="card__title">{title}</h2>
        {action && <div className="card__action">{action}</div>}
      </div>
      <div className="card__body">{children}</div>
    </div>
  );
}
