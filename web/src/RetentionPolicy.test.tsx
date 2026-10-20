import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { RetentionPolicyForm, retentionRequest, retentionFamilies } from "./RetentionPolicy";
import type { RetentionPolicy } from "./RetentionPolicy";

const value: RetentionPolicy = {
  revision: 7, global_days: 90, per_type: { traffic: 60, system: 365, dns: 30 },
  engine: { mode: "partition" }, status: { state: "awaiting_cleanup", message: "Physical part cleanup is pending." },
};

describe("existing-data retention control", () => {
  it("sends explicit confirmation and expected revision, excluding observations", () => {
    expect(() => retentionRequest(value, false)).toThrow("Confirm");
    expect(retentionRequest(value, true)).toEqual({ expected_revision: 7, global_days: 90, per_type: value.per_type, apply_existing: true });
    for (const global_days of [30, 60, 90, 180, 365, 123, 1, 3650]) {
      expect(retentionRequest({ ...value, global_days }, true).global_days).toBe(global_days);
    }
    for (const global_days of [0, -1, 1.5, 3651, NaN]) expect(() => retentionRequest({ ...value, global_days }, true)).toThrow();
    expect(() => retentionRequest({ ...value, engine: { mode: "migrating" } }, true)).toThrow("migration");
  });
  it("edits System once and preserves physical DNS policy", () => {
    expect(retentionFamilies).toHaveLength(15);
    expect(retentionFamilies.some(([id]) => id === "alarms" || id === "unified")).toBe(false);
    const html = renderToStaticMarkup(<RetentionPolicyForm value={{ ...value, legacy_alarms_days: 7 }} role="ADMINISTRATOR" onSave={async () => {}} />);
    expect(html).toContain("System (including System alerts) retention days");
    expect(html).toContain("was never applied");
    expect(html).toContain("DNS events keep DNS retention");
    expect(html).toContain("cannot restore deleted data");
    expect(html).toContain('type="checkbox"');
    expect(html).toContain('class="primary" disabled=""');
    expect(html).not.toContain("new arrivals only");
  });
  it("keeps nonadmins and migration-held controls read-only", () => {
    for (const role of ["VIEWER", "ANALYST"]) {
      const html = renderToStaticMarkup(<RetentionPolicyForm value={value} role={role} onSave={async () => {}} />);
      expect(html).toContain('<fieldset disabled="">');
      expect(html).not.toContain("Save retention policy");
      expect(html).not.toContain('type="checkbox"');
    }
    const html = renderToStaticMarkup(<RetentionPolicyForm value={{ ...value, engine: { mode: "migrating" } }} role="ADMINISTRATOR" onSave={async () => {}} />);
    expect(html).toContain("Retention migration is incomplete");
    expect(html).toContain('<fieldset disabled="">');
    expect(html).toContain("recorded observation");
  });
});
