import { useRef, useState } from "react";
import { uploadSample } from "../api";
import type { Verdict } from "../types";

export function UploadPanel({ onVerdict }: { onVerdict: (v: Verdict) => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleUpload() {
    const file = inputRef.current?.files?.[0];
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const verdict = await uploadSample(file);
      onVerdict(verdict);
    } catch (e) {
      setError(e instanceof Error ? e.message : "upload failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <input ref={inputRef} type="file" disabled={busy} />
      <button onClick={handleUpload} disabled={busy}>
        {busy ? "Detonating in shadow node..." : "Upload sample"}
      </button>
      {error && <p style={{ color: "red" }}>{error}</p>}
    </div>
  );
}
