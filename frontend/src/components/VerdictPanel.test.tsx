import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Verdict } from "../types";
import { VerdictPanel } from "./VerdictPanel";

const base: Verdict = {
  verdict_id: "v1",
  sample_hash: "a".repeat(64),
  sample_filename: "f.sh",
  verdict: "Compromised",
  confidence: 1,
  causal_chain: [],
  timestamp: "2026-10-22T00:00:00Z",
  prev_log_hash: "0".repeat(64),
  detection_method: "dynamic",
  source: "sample",
};

describe("VerdictPanel detection method badge", () => {
  it.each([
    ["known_bad_hash", "known-bad match"],
    ["static_triage", "instant static match (not detonated)"],
    ["dynamic", "detonated &amp; scored"],
  ])("renders %s as %s", (method, label) => {
    const html = renderToStaticMarkup(<VerdictPanel verdict={{ ...base, detection_method: method }} />);
    expect(html).toContain(`data-method="${method}"`);
    expect(html).toContain(label);
  });

  it("renders no badge for an unknown method", () => {
    const html = renderToStaticMarkup(<VerdictPanel verdict={{ ...base, detection_method: "something_new" }} />);
    expect(html).not.toContain("verdict-method");
  });
});
