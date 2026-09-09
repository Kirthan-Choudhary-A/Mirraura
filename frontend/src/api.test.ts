import { describe, expect, it, vi, beforeEach } from "vitest";
import { approveHash, fetchHashes, fetchVerdicts, rejectHash, uploadSample } from "./api";

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
