import { useEffect, useState } from "react";
import { approveHash, fetchHashes, rejectHash, submitHash } from "../api";
import type { HashEntry } from "../api";

export function PendingHashApprovals({ refreshKey }: { refreshKey: number }) {
  const [entries, setEntries] = useState<HashEntry[]>([]);
  const [hashInput, setHashInput] = useState("");
  const [labelInput, setLabelInput] = useState("");
  const [busyHash, setBusyHash] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function refetch() {
    fetchHashes()
      .then(setEntries)
      .catch(() => setEntries([]));
  }

  useEffect(refetch, [refreshKey]);

  const pending = entries.filter((e) => e.status === "pending");

  async function handleDecision(hash: string, decide: (h: string) => Promise<void>) {
    setBusyHash(hash);
    setError(null);
    try {
      await decide(hash);
      refetch();
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
    <div>
      <h2>Pending Hash Approvals</h2>
      {pending.length === 0 && <p>No pending hashes.</p>}
      {pending.length > 0 && (
        <table>
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
                <td>{e.hash.slice(0, 12)}...</td>
                <td>{e.label}</td>
                <td>{e.source}</td>
                <td>{e.proposed_at}</td>
                <td>
                  <button
                    disabled={busyHash === e.hash}
                    onClick={() => handleDecision(e.hash, approveHash)}
                  >
                    Approve
                  </button>
                  <button
                    disabled={busyHash === e.hash}
                    onClick={() => handleDecision(e.hash, rejectHash)}
                    style={{ marginLeft: "0.5rem" }}
                  >
                    Reject
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form onSubmit={handleSubmit} style={{ marginTop: "0.75rem" }}>
        <input
          placeholder="sha256 hash"
          value={hashInput}
          onChange={(e) => setHashInput(e.target.value)}
        />
        <input
          placeholder="label"
          value={labelInput}
          onChange={(e) => setLabelInput(e.target.value)}
          style={{ marginLeft: "0.5rem" }}
        />
        <button type="submit" style={{ marginLeft: "0.5rem" }}>
          Submit for approval
        </button>
      </form>
      {error && <p style={{ color: "#c0392b" }}>{error}</p>}
    </div>
  );
}
