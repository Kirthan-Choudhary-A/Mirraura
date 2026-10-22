import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Verdict } from "../types";
import { DetectionsOverview } from "./DetectionsOverview";

function makeVerdict(overrides: Partial<Verdict>): Verdict {
  return {
    verdict_id: "v1",
    sample_hash: "a".repeat(64),
    sample_filename: "f.sh",
    verdict: "Normal",
    confidence: 0,
    causal_chain: [],
    timestamp: "2026-10-22T00:00:00Z",
    prev_log_hash: "0".repeat(64),
    detection_method: "dynamic",
    source: "sample",
    ...overrides,
  };
}

describe("DetectionsOverview", () => {
  it("counts verdicts by source and detection method", () => {
    const verdicts = [
      makeVerdict({ source: "sample", detection_method: "known_bad_hash" }),
      makeVerdict({ source: "sample", detection_method: "static_triage" }),
      makeVerdict({ source: "monitor", detection_method: "dynamic" }),
    ];
    const html = renderToStaticMarkup(<DetectionsOverview verdicts={verdicts} />);

    expect(html).toContain("Upload / intercept");
    expect(html).toContain("Continuous monitoring");
    expect(html).toContain("Known-bad hash");
    expect(html).toContain("Static triage");
    expect(html).toContain("Detonated &amp; scored");
  });

  it("renders nothing broken for an empty list", () => {
    const html = renderToStaticMarkup(<DetectionsOverview verdicts={[]} />);
    expect(html).toContain('data-testid="detections-overview"');
  });

  it("falls back to the raw value for an unrecognized source or method", () => {
    const html = renderToStaticMarkup(
      <DetectionsOverview verdicts={[makeVerdict({ source: "carrier_pigeon", detection_method: "guesswork" })]} />,
    );
    expect(html).toContain("carrier_pigeon");
    expect(html).toContain("guesswork");
  });
});
