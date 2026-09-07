import type { MirraEvent } from "../types";

export function EventFeed({ events }: { events: MirraEvent[] }) {
  return (
    <div>
      <h2>Live Event Feed</h2>
      <ul>
        {events.map((e) => (
          <li key={e.event_id}>
            [{e.timestamp}] {e.event_type}
            {e.process_ref && ` — process '${e.process_ref.name}' (pid ${e.process_ref.pid})`}
            {e.file_ref && ` — ${e.file_ref.action} '${e.file_ref.path}'`}
            {e.network_ref && ` — connect ${e.network_ref.dst_ip}:${e.network_ref.dst_port}`}
          </li>
        ))}
      </ul>
    </div>
  );
}
