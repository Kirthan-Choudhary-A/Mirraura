import { useEffect, useState } from "react";
import { approveHash, fetchHashes, rejectHash, submitHash } from "../api";
import type { HashEntry } from "../api";

export function PendingHashApprovals({
  refreshKey,
  onDecision,
}: {
  refreshKey: number;
  onDecision: () => void;
}) {
  const [entries, setEntries] = useState<HashEntry[]>([]);
  const [hashInput, setHashInput] = useState("");
  const [labelInput, setLabelInput] = useState("");
  const [busyHash, setBusyHash] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function refetch() {
    fetchHashes()
      .then((entries) => {
        setEntries(entries);
        setError(null);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load pending hashes"));
  }

  useEffect(refetch, [refreshKey]);

  const pending = entries.filter((e) => e.status === "pending");

  async function handleDecision(hash: string, decide: (h: string) => Promise<void>) {
    setBusyHash(hash);
    setError(null);
    try {
      await decide(hash);
      refetch();
      onDecision();
    } catch (e) {
      setError(e instanceof Error ? e.message : "action failed");
    } finally {
      setBusyHash(null);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await submitHash(hashInput.trim(), labelInput.trim());
      setHashInput("");
      setLabelInput("");
      refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "submit failed");
    }
  }

  return (
    <div className="panel">
      <h2>Pending Hash Approvals</h2>
      {pending.length === 0 && <p className="empty-copy">No hashes awaiting review.</p>}
      {pending.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Hash</th>
                <th>Label</th>
                <th>Source</th>
                <th>Proposed</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {pending.map((e) => (
                <tr key={e.hash}>
                  <td className="mono">{e.hash.slice(0, 12)}...</td>
                  <td className="label-cell">{e.label}</td>
                  <td className="label-cell">{e.source}</td>
                  <td className="mono">{e.proposed_at}</td>
                  <td>
                    <button
                      className="approve-button"
                      disabled={busyHash === e.hash}
                      onClick={() => handleDecision(e.hash, approveHash)}
                    >
                      Approve
                    </button>
                    <button
                      className="reject-button"
                      disabled={busyHash === e.hash}
                      onClick={() => handleDecision(e.hash, rejectHash)}
                    >
                      Reject
                    </button>
                  </td>
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
          onChange={(e) => setHashInput(e.target.value)}
        />
        <input
          placeholder="label"
          value={labelInput}
          onChange={(e) => setLabelInput(e.target.value)}
        />
        <button type="submit">Submit for approval</button>
      </form>
      {error && <p className="error-text">{error}</p>}
    </div>
  );
}
