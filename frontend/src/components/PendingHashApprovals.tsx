import { useEffect, useState } from "react";
import { ApiError, approveHash, fetchHashes, isValidSha256, rejectHash, submitHash } from "../api";
import type { HashEntry } from "../api";
import { Card } from "./Card";
import { ConfirmDialog } from "./ConfirmDialog";
import { CopyHash } from "./CopyHash";
import { Skeleton } from "./Skeleton";
import { useToast } from "./Toast";
import "./PendingHashApprovals.css";

type PendingAction = { hash: string; label: string; decide: (h: string) => Promise<void>; verb: string };

export function PendingHashApprovals({
  refreshKey,
  role,
  onDecision,
  onSessionExpired,
  onHashesChange,
}: {
  refreshKey: number;
  role: "admin" | "analyst";
  onDecision: () => void;
  onSessionExpired?: () => void;
  onHashesChange?: (entries: HashEntry[]) => void;
}) {
  const [entries, setEntries] = useState<HashEntry[]>([]);
  const [hashInput, setHashInput] = useState("");
  const [labelInput, setLabelInput] = useState("");
  const [hashError, setHashError] = useState<string | null>(null);
  const [busyHash, setBusyHash] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [loading, setLoading] = useState(true);
  const { push } = useToast();

  function refetch() {
    fetchHashes()
      .then((entries) => {
        setEntries(entries);
        onHashesChange?.(entries);
        setError(null);
      })
      .catch((e) => {
        if (e instanceof ApiError && e.status === 401) return onSessionExpired?.();
        if (e instanceof ApiError && e.status === 403) return push("Admins only", "error");
        setError(e instanceof Error ? e.message : "failed to load pending hashes");
      })
      .finally(() => setLoading(false));
  }

  useEffect(refetch, [refreshKey]);

  const pending = entries.filter((e) => e.status === "pending");

  async function runDecision(hash: string, decide: (h: string) => Promise<void>) {
    setBusyHash(hash);
    setError(null);
    try {
      await decide(hash);
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
      setBusyHash(null);
      setPendingAction(null);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const hash = hashInput.trim();
    if (!isValidSha256(hash)) {
      setHashError("Must be 64 lowercase hex characters (a SHA-256 hash).");
      return;
    }
    setHashError(null);
    try {
      await submitHash(hash, labelInput.trim());
      setHashInput("");
      setLabelInput("");
      refetch();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onSessionExpired?.();
      } else if (err instanceof ApiError && err.status === 403) {
        push("Admins only", "error");
      } else {
        setError(err instanceof Error ? err.message : "submit failed");
      }
    }
  }

  return (
    <Card title="Pending hash approvals" action={<span className="pending-count mono">{pending.length}</span>}>
      {error && <p className="error-text">{error}</p>}
      {loading ? (
        <Skeleton rows={3} />
      ) : pending.length === 0 ? (
        <p className="empty-copy">No hashes awaiting review.</p>
      ) : (
        <div className="table-scroll">
          <table className="hash-table">
            <thead>
              <tr>
                <th>Hash</th>
                <th>Label</th>
                <th>Source</th>
                <th>Proposed</th>
                {role === "admin" && <th>Action</th>}
              </tr>
            </thead>
            <tbody>
              {pending.map((e) => (
                <tr key={e.hash}>
                  <td>
                    <CopyHash hash={e.hash} label="Proposed hash" />
                  </td>
                  <td>{e.label}</td>
                  <td>{e.source}</td>
                  <td className="mono">{e.proposed_at}</td>
                  {role === "admin" && (
                    <td>
                      <button
                        type="button"
                        className="approve-button"
                        disabled={busyHash === e.hash}
                        onClick={() =>
                          setPendingAction({ hash: e.hash, label: e.label, decide: approveHash, verb: "Approve" })
                        }
                      >
                        Approve
                      </button>
                      <button
                        type="button"
                        className="reject-button"
                        disabled={busyHash === e.hash}
                        onClick={() =>
                          setPendingAction({ hash: e.hash, label: e.label, decide: rejectHash, verb: "Reject" })
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

      <form onSubmit={handleSubmit} className="hash-form">
        <input
          placeholder="sha256 hash"
          value={hashInput}
          onChange={(e) => {
            setHashInput(e.target.value);
            if (hashError) setHashError(null);
          }}
          aria-invalid={hashError ? true : undefined}
        />
        <input
          placeholder="label"
          value={labelInput}
          onChange={(e) => setLabelInput(e.target.value)}
        />
        <button type="submit">Submit for approval</button>
      </form>
      {hashError && <p className="error-text">{hashError}</p>}

      <ConfirmDialog
        open={pendingAction !== null}
        title={`${pendingAction?.verb ?? ""} this hash?`}
        description={
          pendingAction && (
            <>
              <p className="mono confirm-dialog__hash">{pendingAction.hash}</p>
              <p>{pendingAction.label || "(no label)"}</p>
            </>
          )
        }
        confirmLabel={pendingAction?.verb ?? "Confirm"}
        onConfirm={() => pendingAction && runDecision(pendingAction.hash, pendingAction.decide)}
        onCancel={() => setPendingAction(null)}
      />
    </Card>
  );
}
