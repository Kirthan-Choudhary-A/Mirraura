import { useEffect, useState } from "react";
import { ApiError, approveQuarantine, fetchQuarantinePending, rejectQuarantine } from "../api";
import type { QuarantineEntry } from "../api";
import { Card } from "./Card";
import { ConfirmDialog } from "./ConfirmDialog";
import { CopyHash } from "./CopyHash";
import { Skeleton } from "./Skeleton";
import { useToast } from "./Toast";
import "./PendingHashApprovals.css";

type PendingAction = { id: number; filename: string; decide: (id: number) => Promise<void>; verb: string };

export function QuarantineReview({
  refreshKey,
  role,
  onDecision,
  onSessionExpired,
  onQuarantineChange,
}: {
  refreshKey: number;
  role: "admin" | "analyst";
  onDecision: () => void;
  onSessionExpired?: () => void;
  onQuarantineChange?: (entries: QuarantineEntry[]) => void;
}) {
  const [entries, setEntries] = useState<QuarantineEntry[]>([]);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [loading, setLoading] = useState(true);
  const { push } = useToast();

  function refetch() {
    fetchQuarantinePending()
      .then((entries) => {
        setEntries(entries);
        onQuarantineChange?.(entries);
        setError(null);
      })
      .catch((e) => {
        if (e instanceof ApiError && e.status === 401) return onSessionExpired?.();
        if (e instanceof ApiError && e.status === 403) return push("Admins only", "error");
        setError(e instanceof Error ? e.message : "failed to load quarantined files");
      })
      .finally(() => setLoading(false));
  }

  useEffect(refetch, [refreshKey]);

  async function runDecision(id: number, decide: (id: number) => Promise<void>) {
    setBusyId(id);
    setError(null);
    try {
      await decide(id);
      refetch();
      onDecision();
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        onSessionExpired?.();
      } else if (e instanceof ApiError && e.status === 403) {
        push("Admins only", "error");
      } else {
        setError(e instanceof Error ? e.message : "action failed");
      }
    } finally {
      setBusyId(null);
      setPendingAction(null);
    }
  }

  return (
    <Card title="Quarantined downloads" action={<span className="pending-count mono">{entries.length}</span>}>
      {error && <p className="error-text">{error}</p>}
      {loading ? (
        <Skeleton rows={3} />
      ) : entries.length === 0 ? (
        <p className="empty-copy">No files awaiting review. Anything the interceptor couldn't confidently clear or condemn shows up here.</p>
      ) : (
        <div className="table-scroll">
          <table className="hash-table">
            <thead>
              <tr>
                <th>File</th>
                <th>Hash</th>
                <th>Verdict</th>
                <th>Original path</th>
                <th>Quarantined</th>
                {role === "admin" && <th>Action</th>}
              </tr>
            </thead>
            <tbody>
              {entries.map((q) => (
                <tr key={q.id}>
                  <td>{q.filename}</td>
                  <td>
                    <CopyHash hash={q.sample_hash} label="Quarantined file hash" />
                  </td>
                  <td>
                    {q.verdict_label} <span className="mono">({q.confidence.toFixed(2)})</span>
                  </td>
                  <td className="mono">{q.original_path}</td>
                  <td className="mono">{q.created_at}</td>
                  {role === "admin" && (
                    <td>
                      <button
                        type="button"
                        className="approve-button"
                        disabled={busyId === q.id}
                        onClick={() =>
                          setPendingAction({ id: q.id, filename: q.filename, decide: approveQuarantine, verb: "Approve" })
                        }
                      >
                        Approve
                      </button>
                      <button
                        type="button"
                        className="reject-button"
                        disabled={busyId === q.id}
                        onClick={() =>
                          setPendingAction({ id: q.id, filename: q.filename, decide: rejectQuarantine, verb: "Reject" })
                        }
                      >
                        Reject
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={pendingAction !== null}
        title={`${pendingAction?.verb ?? ""} this file?`}
        description={
          pendingAction && (
            <>
              <p>{pendingAction.filename}</p>
              <p>
                {pendingAction.verb === "Approve"
                  ? "It will be released back to its original location."
                  : "It stays quarantined and will not be released."}
              </p>
            </>
          )
        }
        confirmLabel={pendingAction?.verb ?? "Confirm"}
        onConfirm={() => pendingAction && runDecision(pendingAction.id, pendingAction.decide)}
        onCancel={() => setPendingAction(null)}
      />
    </Card>
  );
}
