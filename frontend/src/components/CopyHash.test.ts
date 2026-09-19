import { describe, expect, it } from "vitest";
import { truncateMiddle } from "./CopyHash";

describe("truncateMiddle", () => {
  it("truncates a long hash to the given keep length on each side", () => {
    const hash = "a".repeat(32) + "b".repeat(32);
    expect(truncateMiddle(hash, 6)).toBe("aaaaaa…bbbbbb");
  });

  it("returns short strings unchanged", () => {
    expect(truncateMiddle("short", 6)).toBe("short");
  });
});
