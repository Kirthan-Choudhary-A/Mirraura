import { describe, expect, it, vi, beforeEach } from "vitest";
import { fetchVerdicts, uploadSample } from "./api";

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
});
