import { describe, expect, it, vi, beforeEach } from "vitest";
import { approveHash, fetchHashes, fetchVerdicts, fetchMonitorStatus, rejectHash, uploadSample } from "./api";
import { applyLiveEvent, nextBackoffMs, shouldUpdateSampleVerdict } from "./api";
import { ApiError, request } from "./api";
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
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/verdicts"),
      expect.objectContaining({ credentials: "same-origin" })
    );
    expect(result).toEqual([{ verdict_id: "v1" }]);
  });

  it("fetchVerdicts throws when the response is not ok", async () => {
    (fetch as any).mockResolvedValue({ ok: false, text: async () => "boom" });
    await expect(fetchVerdicts()).rejects.toThrow("boom");
  });

  it("fetchMonitorStatus throws when the response is not ok", async () => {
    (fetch as any).mockResolvedValue({ ok: false, text: async () => "boom" });
    await expect(fetchMonitorStatus()).rejects.toThrow("boom");
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
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/hashes"),
      expect.objectContaining({ credentials: "same-origin" })
    );
    expect(result).toEqual([{ hash: "a".repeat(64), status: "pending" }]);
  });

  it("approveHash posts to the hash-specific approve endpoint", async () => {
    (fetch as any).mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await approveHash("abc123");
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/hashes/abc123/approve"),
      expect.objectContaining({ method: "POST" })
    );
  });

  it("rejectHash posts to the hash-specific reject endpoint", async () => {
    (fetch as any).mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await rejectHash("abc123");
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/hashes/abc123/reject"),
      expect.objectContaining({ method: "POST" })
    );
  });
});

describe("request", () => {
  it("returns parsed JSON on a successful response", async () => {
    (fetch as any).mockResolvedValue({ ok: true, status: 200, json: async () => ({ a: 1 }) });
    const result = await request<{ a: number }>("/api/whatever");
    expect(result).toEqual({ a: 1 });
  });

  it("throws an ApiError with the status code on a 401", async () => {
    (fetch as any).mockResolvedValue({ ok: false, status: 401, text: async () => "unauthorized" });
    await expect(request("/api/whatever")).rejects.toMatchObject({ status: 401, message: "unauthorized" });
  });

  it("throws an ApiError with the status code on a 403", async () => {
    (fetch as any).mockResolvedValue({ ok: false, status: 403, text: async () => "forbidden" });
    await expect(request("/api/whatever")).rejects.toMatchObject({ status: 403 });
  });

  it("thrown errors are instances of ApiError", async () => {
    (fetch as any).mockResolvedValue({ ok: false, status: 500, text: async () => "boom" });
    await expect(request("/api/whatever")).rejects.toBeInstanceOf(ApiError);
  });

  it("resolves to undefined on a 204 No Content response with no body", async () => {
    (fetch as any).mockResolvedValue({ ok: true, status: 204 });
    const result = await request("/api/logout", { method: "POST" });
    expect(result).toBeUndefined();
  });

  it("always sends credentials: same-origin", async () => {
    (fetch as any).mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await request("/api/whatever");
    expect(fetch).toHaveBeenCalledWith("/api/whatever", expect.objectContaining({ credentials: "same-origin" }));
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
