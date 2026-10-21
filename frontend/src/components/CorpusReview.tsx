import { useEffect, useState } from "react";
import {
  ApiError,
  MAX_CORPUS_SAMPLE_BYTES,
  approveCorpusEntry,
  fetchCorpusPending,
  rejectCorpusEntry,
  submitCorpusSample,
} from "../api";
import type { CorpusEntry } from "../api";
import { Card } from "./Card";
import { ConfirmDialog } from "./ConfirmDialog";
import { CopyHash } from "./CopyHash";
import { Skeleton } from "./Skeleton";
import { useToast } from "./Toast";
import "./PendingHashApprovals.css";

type PendingAction = { contentHash: string; label: string; preview: string; decide: (h: string) => Promise<void>; verb: string };

export function CorpusReview({
  refreshKey,
  role,
  onDecision,
  onSessionExpired,
  onCorpusChange,
}: {
  refreshKey: number;
  role: "admin" | "analyst";
  onDecision: () => void;
  onSessionExpired?: () => void;
  onCorpusChange?: (entries: CorpusEntry[]) => void;
}) {
  const [entries, setEntries] = useState<CorpusEntry[]>([]);
  const [fileInput, setFileInput] = useState<File | null>(null);
  const [labelInput, setLabelInput] = useState("");
  const [fileError, setFileError] = useState<string | null>(null);
  const [formKey, setFormKey] = useState(0);
  const [busyHash, setBusyHash] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [loading, setLoading] = useState(true);
  const { push } = useToast();

  function refetch() {
    fetchCorpusPending()
      .then((entries) => {
        setEntries(entries);
        onCorpusChange?.(entries);
        setError(null);
      })
      .catch((e) => {
        if (e instanceof ApiError && e.status === 401) return onSessionExpired?.();
        if (e instanceof ApiError && e.status === 403) return push("Admins only", "error");
        setError(e instanceof Error ? e.message : "failed to load pending corpus samples");
      })
      .finally(() => setLoading(false));
  }

  useEffect(refetch, [refreshKey]);

  async function runDecision(contentHash: string, decide: (h: string) => Promise<void>) {
    setBusyHash(contentHash);
    setError(null);
    try {
      await decide(contentHash);
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
    if (!fileInput) {
      setFileError("Choose a sample file.");
      return;
    }
    if (fileInput.size === 0 || fileInput.size > MAX_CORPUS_SAMPLE_BYTES) {
      setFileError(`Sample must be between 1 byte and ${MAX_CORPUS_SAMPLE_BYTES / 1024} KB.`);
      return;
    }
    setFileError(null);
    try {
      await submitCorpusSample(fileInput, labelInput.trim());
      setFileInput(null);
      setLabelInput("");
      setFormKey((k) => k + 1); // file inputs can't be cleared via value; remount it
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
    <Card title="Pending corpus samples" action={<span className="pending-count mono">{entries.length}</span>}>
      {error && <p className="error-text">{error}</p>}
      {loading ? (
        <Skeleton rows={3} />
      ) : entries.length === 0 ? (
        <p className="empty-copy">No samples awaiting review. Approved samples are matched by content similarity before detonation.</p>
      ) : (
        <div className="table-scroll">
          <table className="hash-table">
            <thead>
              <tr>
                <th>Hash</th>
                <th>Label</th>
                <th>Preview</th>
                <th>Size</th>
                <th>Proposed</th>
                {role === "admin" && <th>Action</th>}
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.content_hash}>
                  <td>
                    <CopyHash hash={e.content_hash} label="Sample content hash" />
                  </td>
                  <td>{e.label}</td>
                  <td className="mono">{e.preview}</td>
                  <td className="mono">{e.size} B</td>
                  <td className="mono">{e.proposed_at}</td>
                  {role === "admin" && (
                    <td>
                      <button
                        type="button"
                        className="approve-button"
                        disabled={busyHash === e.content_hash}
                        onClick={() =>
                          setPendingAction({
                            contentHash: e.content_hash,
                            label: e.label,
                            preview: e.preview,
                            decide: approveCorpusEntry,
                            verb: "Approve",
                          })
                        }
                      >
                        Approve
                      </button>
                      <button
                        type="button"
                        className="reject-button"
                        disabled={busyHash === e.content_hash}
                        onClick={() =>
                          setPendingAction({
                            contentHash: e.content_hash,
                            label: e.label,
                            preview: e.preview,
                            decide: rejectCorpusEntry,
                            verb: "Reject",
                          })
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
          key={formKey}
          type="file"
          aria-label="sample file"
          onChange={(e) => {
            setFileInput(e.target.files?.[0] ?? null);
            if (fileError) setFileError(null);
          }}
          aria-invalid={fileError ? true : undefined}
        />
        <input placeholder="label" value={labelInput} onChange={(e) => setLabelInput(e.target.value)} />
        <button type="submit">Submit for approval</button>
      </form>
      {fileError && <p className="error-text">{fileError}</p>}

      <ConfirmDialog
        open={pendingAction !== null}
        title={`${pendingAction?.verb ?? ""} this sample?`}
        description={
          pendingAction && (
            <>
              <p className="mono confirm-dialog__hash">{pendingAction.contentHash}</p>
              <p>{pendingAction.label || "(no label)"}</p>
              <pre className="mono">{pendingAction.preview}</pre>
              <p>
                {pendingAction.verb === "Approve"
                  ? "Uploads at least 85% similar to this will be marked Compromised without detonation."
                  : "It will not be used for similarity matching."}
              </p>
            </>
          )
        }
        confirmLabel={pendingAction?.verb ?? "Confirm"}
        onConfirm={() => pendingAction && runDecision(pendingAction.contentHash, pendingAction.decide)}
        onCancel={() => setPendingAction(null)}
      />
    </Card>
  );
}
