import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { EmergencyObservation, emergencyObservationFresh } from "./EmergencyStorage";

const now = Date.parse("2026-10-15T19:00:00Z");
const observed = {
  state: "normal", observed_at: new Date(now).toISOString(),
  message: "Log disk is below the cleanup threshold.", used_percent: 42,
};

describe("emergency cleanup observation", () => {
  it("expires a previous normal result when the worker stops checking", () => {
    expect(emergencyObservationFresh(observed, now + 120_000)).toBe(true);
    expect(emergencyObservationFresh(observed, now + 120_001)).toBe(false);
    const html = renderToStaticMarkup(<EmergencyObservation value={observed} now={now + 120_001} />);
    expect(html).not.toContain(observed.message);
    expect(html).not.toContain("42.0% used");
    expect(html).toContain("recent controller result is unavailable");
  });
  it("rejects absent, malformed and future evidence", () => {
    for (const observed_at of [undefined, null, "invalid", new Date(now + 5_001).toISOString()]) {
      expect(emergencyObservationFresh({ ...observed, observed_at }, now)).toBe(false);
    }
  });
  it("keeps measured disk scope and zero utilization explicit", () => {
    const html = renderToStaticMarkup(<EmergencyObservation value={{ ...observed, used_percent: 0 }} now={now} />);
    expect(html).toContain("0.0% used on the log disk");
    expect(html).toContain(observed.message);
  });
  it("renders blocked recovery evidence as an explanation without a purge control", () => {
    const html = renderToStaticMarkup(<EmergencyObservation value={{ ...observed, state: "blocked", message: "An earlier deletion has an uncertain outcome. Ingestion is retaining queued events." }} now={now} />);
    expect(html).toContain("uncertain outcome");
    expect(html).toContain("blocked");
    expect(html).not.toContain("<button");
  });
  it("exposes unresolved inserts only while their observation remains fresh", () => {
    const value = { ...observed, insert_exclusions: 3, exclusion_message: "Affected partitions are protected while insert outcomes are unknown." };
    const render = (clock: number) => renderToStaticMarkup(<EmergencyObservation value={value} now={clock} />);
    expect(render(now)).toContain("3 unresolved insert reservations.");
    expect(render(now)).toContain(value.exclusion_message);
    expect(render(now + 120_001)).not.toContain(value.exclusion_message);
  });
  it("distinguishes a maintenance hold from a stale observation without a clear control", () => {
    const value = { ...observed, maintenance_held: true, delivery_held: true };
    const render = (clock: number) => renderToStaticMarkup(<EmergencyObservation value={value} now={clock} />);
    expect(render(now)).toContain("Appliance maintenance is active.");
    expect(render(now)).toContain("log delivery are paused; queued logs are retained");
    expect(render(now)).not.toContain("<button");
    expect(render(now + 120_001)).not.toContain("Appliance maintenance is active.");
  });
});
