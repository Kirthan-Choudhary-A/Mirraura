import { describe, expect, it, vi, beforeEach } from "vitest";
import { approveHash, fetchHashes, fetchVerdicts, rejectHash, uploadSample } from "./api";
import { applyLiveEvent, nextBackoffMs, shouldUpdateSampleVerdict } from "./api";
import type { MirraEvent, Verdict } from "./types";

function makeEvent(id: string): MirraEvent {
  return {
    event_id: id,
    device_id: "d1",
    event_type: "process_spawn",
    timestamp: "2026-09-18T00:00:00Z",
    baseline_deviation_score: 0,
  };
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});

describe("api", () => {
  it("fetchVerdicts calls the backend verdicts endpoint", async () => {
    (fetch as any).mockResolvedValue({
      ok: true,
      json: async () => [{ verdict_id: "v1" }],
    });
    const result = await fetchVerdicts();
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/verdicts"));
    expect(result).toEqual([{ verdict_id: "v1" }]);
  });

  it("uploadSample posts multipart form data and returns the verdict", async () => {
    (fetch as any).mockResolvedValue({
      ok: true,
      json: async () => ({ verdict_id: "v2", verdict: "Normal" }),
    });
    const file = new File(["content"], "sample.sh");
    const result = await uploadSample(file);
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/samples"),
      expect.objectContaining({ method: "POST" })
    );
    expect(result.verdict).toBe("Normal");
  });

  it("fetchHashes calls the backend hashes endpoint", async () => {
    (fetch as any).mockResolvedValue({
      ok: true,
      json: async () => [{ hash: "a".repeat(64), status: "pending" }],
    });
    const result = await fetchHashes();
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/hashes"));
    expect(result).toEqual([{ hash: "a".repeat(64), status: "pending" }]);
  });

  it("approveHash posts to the hash-specific approve endpoint", async () => {
    (fetch as any).mockResolvedValue({ ok: true, text: async () => "" });
    await approveHash("abc123");
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/hashes/abc123/approve"),
      expect.objectContaining({ method: "POST" })
    );
  });

  it("rejectHash posts to the hash-specific reject endpoint", async () => {
    (fetch as any).mockResolvedValue({ ok: true, text: async () => "" });
    await rejectHash("abc123");
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/hashes/abc123/reject"),
      expect.objectContaining({ method: "POST" })
    );
  });
});

describe("applyLiveEvent", () => {
  it("appends a sample-source event", () => {
    const result = applyLiveEvent([], { type: "event", source: "sample", data: makeEvent("e1") });
    expect(result).toHaveLength(1);
  });

  it("ignores a monitor-source event", () => {
    const result = applyLiveEvent([], { type: "event", source: "monitor", data: makeEvent("e1") });
    expect(result).toHaveLength(0);
  });

  it("ignores non-event messages", () => {
    const result = applyLiveEvent([makeEvent("e1")], { type: "isolated" });
    expect(result).toHaveLength(1);
  });

  it("caps the result at 500 events", () => {
    const existing = Array.from({ length: 500 }, (_, i) => makeEvent(`e${i}`));
    const result = applyLiveEvent(existing, { type: "event", source: "sample", data: makeEvent("new") });
    expect(result).toHaveLength(500);
    expect(result[result.length - 1].event_id).toBe("new");
    expect(result[0].event_id).toBe("e1");
  });
});

describe("shouldUpdateSampleVerdict", () => {
  const verdict: Verdict = {
    verdict_id: "v1",
    sample_hash: "a".repeat(64),
    sample_filename: "f.sh",
    verdict: "Normal",
    confidence: 0,
    causal_chain: [],
    timestamp: "2026-09-18T00:00:00Z",
    prev_log_hash: "0".repeat(64),
  };

  it("is true for a sample-source verdict", () => {
    expect(shouldUpdateSampleVerdict({ type: "verdict", source: "sample", data: verdict })).toBe(true);
  });

  it("is false for a monitor-source verdict", () => {
    expect(shouldUpdateSampleVerdict({ type: "verdict", source: "monitor", data: verdict })).toBe(false);
  });

  it("is false for a non-verdict message", () => {
    expect(shouldUpdateSampleVerdict({ type: "reconnected" })).toBe(false);
  });
});

describe("nextBackoffMs", () => {
  it("doubles the current delay", () => {
    expect(nextBackoffMs(1000)).toBe(2000);
  });

  it("caps at 30 seconds", () => {
    expect(nextBackoffMs(20000)).toBe(30000);
    expect(nextBackoffMs(30000)).toBe(30000);
  });
});
