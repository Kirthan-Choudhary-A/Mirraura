import { useEffect, useRef, useState } from "react";
import { FileWarning, Network, TerminalSquare } from "lucide-react";
import type { MirraEvent } from "../types";
import { Card } from "./Card";
import { TabPanel, Tabs } from "./Tabs";
import "./EventFeed.css";

type EventTypeFilter = "process_spawn" | "file_write" | "file_delete" | "network_connect";

const FILTER_CHIPS: { id: EventTypeFilter | "network_connect"; label: string }[] = [
  { id: "process_spawn", label: "Process" },
  { id: "file_write", label: "File" },
  { id: "network_connect", label: "Network" },
];

// Mirrors verdict-engine/rule_scorer.py's own constants so a row can name
// the rule it would trigger — not shared code across the Go/Python/TS
// boundary (no mechanism for that in this project), just kept in sync in
// spirit. Rapid-file-changes is deliberately not tagged per-row: it's an
// aggregate count across the whole run, not a single event's property, so
// tagging individual rows for it would misrepresent which row "caused" it.
const SENSITIVE_PREFIXES = ["/etc/", "/bin/", "/usr/", "/boot/", "/sbin/"];
const STANDARD_PORTS = new Set([80, 443]);

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

function ruleTag(e: MirraEvent): string | null {
  if (e.event_type === "process_spawn") return "child process";
  if (e.event_type === "file_write" && e.file_ref && SENSITIVE_PREFIXES.some((p) => e.file_ref!.path.startsWith(p))) {
    return "sensitive path";
  }
  if (e.event_type === "network_connect" && e.network_ref && !STANDARD_PORTS.has(e.network_ref.dst_port)) {
    return "non-standard port";
  }
  return null;
}

function EventIcon({ type }: { type: MirraEvent["event_type"] }) {
  if (type === "process_spawn") return <TerminalSquare size={14} aria-hidden="true" />;
  if (type === "network_connect") return <Network size={14} aria-hidden="true" />;
  return <FileWarning size={14} aria-hidden="true" />;
}

function EventList({ events, emptyMessage }: { events: MirraEvent[]; emptyMessage: string }) {
  const [activeFilters, setActiveFilters] = useState<Set<string>>(new Set(FILTER_CHIPS.map((c) => c.id)));
  const [autoScroll, setAutoScroll] = useState(true);
  const [newCount, setNewCount] = useState(0);
  const listRef = useRef<HTMLUListElement>(null);
  const prevLength = useRef(events.length);

  function toggleFilter(id: string) {
    setActiveFilters((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const filtered = events.filter((e) => activeFilters.has(e.event_type));

  useEffect(() => {
    const added = events.length - prevLength.current;
    prevLength.current = events.length;
    if (added <= 0) return;
    if (autoScroll && listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    } else if (added > 0) {
      setNewCount((n) => n + added);
    }
  }, [events, autoScroll]);

  function handleScroll() {
    const el = listRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setAutoScroll(nearBottom);
    if (nearBottom) setNewCount(0);
  }

  function jumpToBottom() {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight });
    setAutoScroll(true);
    setNewCount(0);
  }

  return (
    <div className="event-feed">
      <div className="event-feed__chips">
        {FILTER_CHIPS.map((chip) => (
          <button
            key={chip.id}
            type="button"
            className="event-feed__chip"
            data-active={activeFilters.has(chip.id)}
            onClick={() => toggleFilter(chip.id)}
          >
            {chip.label}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <p className="trace-empty">{emptyMessage}</p>
      ) : (
        <ul className="trace-list" ref={listRef} onScroll={handleScroll}>
          {filtered.map((e) => {
            const tag = ruleTag(e);
            return (
              <li className="trace-row" key={e.event_id} data-type={e.event_type}>
                <EventIcon type={e.event_type} />
                <span className="trace-row__time mono" title={e.timestamp}>
                  {formatTime(e.timestamp)}
                </span>
                {detail(e) && <span className="trace-row__detail mono">{detail(e)}</span>}
                {tag && <span className="trace-row__tag">{tag}</span>}
              </li>
            );
          })}
        </ul>
      )}

      {!autoScroll && newCount > 0 && (
        <button type="button" className="trace-jump" onClick={jumpToBottom}>
          ↓ {newCount} new event{newCount === 1 ? "" : "s"}
        </button>
      )}
    </div>
  );
}

export function EventFeed({ sampleEvents, monitorEvents }: { sampleEvents: MirraEvent[]; monitorEvents: MirraEvent[] }) {
  const [tab, setTab] = useState<"shadow" | "monitor">("shadow");

  return (
    <Card title="Live telemetry">
      <Tabs
        tabs={[
          { id: "shadow", label: "Shadow run" },
          { id: "monitor", label: "Endpoint monitor" },
        ]}
        active={tab}
        onChange={(id) => setTab(id as "shadow" | "monitor")}
      />
      <TabPanel id="shadow" active={tab}>
        <EventList events={sampleEvents} emptyMessage="No trace yet — upload a sample to begin." />
      </TabPanel>
      <TabPanel id="monitor" active={tab}>
        <EventList events={monitorEvents} emptyMessage="No monitor activity yet." />
      </TabPanel>
    </Card>
  );
}
