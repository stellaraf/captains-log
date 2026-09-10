import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { FreshHostObservation, observationVisibility } from "./FreshHostObservation";

const now = Date.parse("2026-09-08T07:00:00Z");
const measured = (when = now) => ({ status: "observed", observed_at: new Date(when).toISOString() });

describe("security and update observation freshness", () => {
  it("expires successful evidence without requiring another request", () => {
    expect(observationVisibility(measured(), false, now + 90_000).visible).toBe(true);
    expect(observationVisibility(measured(), false, now + 90_001).visible).toBe(false);
  });

  it("masks previous success as soon as refresh fails", () => {
    expect(observationVisibility(measured(), true, now).visible).toBe(false);
    expect(observationVisibility({ status: "unavailable" }, true, now).visible).toBe(false);
  });

  it("refuses missing, future or malformed observation times", () => {
    for (const value of [{ status: "observed" }, { status: "observed", observed_at: "invalid" }, measured(now + 5_001), {}]) {
      expect(observationVisibility(value, false, now).visible).toBe(false);
    }
  });

  it("caps declared lifetimes and honors a shorter expiry", () => {
    expect(observationVisibility({ ...measured(), expires_at: new Date(now + 120_000).toISOString() }, false, now + 90_001).visible).toBe(false);
    expect(observationVisibility({ ...measured(), expires_at: new Date(now + 30_000).toISOString() }, false, now + 30_001).visible).toBe(false);
    for (const expires_at of [null, "invalid", new Date(now - 1).toISOString()]) {
      expect(observationVisibility({ ...measured(), expires_at }, false, now).visible).toBe(false);
    }
  });

  it("preserves explicitly unavailable and disconnected explanations", () => {
    for (const status of ["unavailable", "not_connected"]) expect(observationVisibility({ status }, false, now).visible).toBe(true);
  });

  it("removes expired or failed security claims from the rendered page", () => {
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      const render = (value: Record<string, unknown>, refreshFailed: boolean) => renderToStaticMarkup(
        <FreshHostObservation value={value} refreshFailed={refreshFailed}><div>Verified host result</div></FreshHostObservation>,
      );
      expect(render(measured(), false)).toContain("Verified host result");
      expect(render(measured(now - 90_001), false)).not.toContain("Verified host result");
      expect(render(measured(), true)).not.toContain("Verified host result");
      expect(render(measured(), true)).toContain('role="status"');
    } finally { clock.mockRestore(); }
  });
});
