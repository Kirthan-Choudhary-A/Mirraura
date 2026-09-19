import { useRef, useState } from "react";
import { UploadCloud } from "lucide-react";
import { ApiError, sha256Hex, uploadSample } from "../api";
import type { Verdict } from "../types";
import { Card } from "./Card";
import { CopyHash } from "./CopyHash";
import "./UploadPanel.css";

const STEPS = ["Upload", "Isolate", "Detonate", "Observe", "Score", "Teardown"] as const;

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function UploadPanel({
  onVerdict,
  onUploadStart,
  onSessionExpired,
}: {
  onVerdict: (v: Verdict) => void;
  onUploadStart: () => void;
  onSessionExpired: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [hash, setHash] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Real per-run WebSocket events don't currently mark the container-start
  // or teardown boundaries specifically (only sensor trace events arrive),
  // so this is a timed approximation while the request is in flight rather
  // than a claim of granular real-time tracking — the request only returns
  // once every step has genuinely finished.
  const [stepIndex, setStepIndex] = useState(0);

  async function handleFile(f: File) {
    setFile(f);
    setHash(null);
    setError(null);
    try {
      const h = await sha256Hex(f);
      setHash(h);
    } catch {
      // crypto.subtle unavailable (e.g. non-HTTPS/non-localhost context) —
      // the hash preview just won't show; upload itself is unaffected.
    }
  }

  async function handleUpload() {
    if (!file) return;
    onUploadStart();
    setBusy(true);
    setError(null);
    setStepIndex(0);

    const ticker = setInterval(() => {
      setStepIndex((i) => Math.min(i + 1, STEPS.length - 2));
    }, 700);

    try {
      const verdict = await uploadSample(file);
      setStepIndex(STEPS.length - 1);
      onVerdict(verdict);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        onSessionExpired();
        return;
      }
      setError(e instanceof Error ? e.message : "Upload failed — check your connection and try again.");
    } finally {
      clearInterval(ticker);
      setBusy(false);
    }
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files?.[0];
    if (dropped) handleFile(dropped);
  }

  return (
    <Card title="Detonate a sample">
      <div
        className="upload-drop"
        data-active={dragOver}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
      >
        <UploadCloud className="upload-drop__icon" aria-hidden="true" size={28} />
        <p className="upload-drop__label">Drag a file here, or click to browse</p>
        <input
          ref={inputRef}
          type="file"
          className="upload-drop__input"
          disabled={busy}
          onChange={(e) => {
            const picked = e.target.files?.[0];
            if (picked) handleFile(picked);
          }}
        />
      </div>

      {file && (
        <dl className="upload-file-info">
          <dt>File</dt>
          <dd className="mono">
            {file.name} · {formatSize(file.size)}
          </dd>
          {hash && (
            <>
              <dt>SHA-256</dt>
              <dd>
                <CopyHash hash={hash} label="Sample hash" />
              </dd>
            </>
          )}
        </dl>
      )}

      <button className="run-button" onClick={handleUpload} disabled={busy || !file}>
        {busy && <span className="spinner" aria-hidden="true" />}
        {busy ? "Detonating…" : "Run sample"}
      </button>

      {busy && (
        <ol className="upload-steps" aria-label="Detonation progress">
          {STEPS.map((step, i) => (
            <li key={step} data-state={i < stepIndex ? "done" : i === stepIndex ? "active" : "pending"}>
              {step}
            </li>
          ))}
        </ol>
      )}

      {error && <p className="error-text">{error}</p>}
    </Card>
  );
}
