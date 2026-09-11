import type { MirraEvent } from "../types";

function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

function detail(e: MirraEvent): string | null {
  if (e.process_ref) return `${e.process_ref.name} (pid ${e.process_ref.pid})`;
  if (e.file_ref) return `${e.file_ref.action} '${e.file_ref.path}'`;
  if (e.network_ref) return `connect ${e.network_ref.dst_ip}:${e.network_ref.dst_port}`;
  return null;
}

export function EventFeed({ events }: { events: MirraEvent[] }) {
  return (
    <div className="trace-panel">
      <h2>Live Event Feed</h2>
      {events.length === 0 ? (
        <p className="trace-empty">No trace yet — upload a sample to begin.</p>
      ) : (
        <ul className="trace-list">
          {events.map((e) => (
            <li className="trace-row" key={e.event_id}>
              <span className="trace-row__time">{formatTime(e.timestamp)}</span>
              <span className="trace-row__type">{e.event_type}</span>
              {detail(e) && <span className="trace-row__detail">{detail(e)}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
