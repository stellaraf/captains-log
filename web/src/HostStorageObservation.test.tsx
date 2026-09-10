import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { HostStorageObservation, storageObservation } from "./HostStorageObservation";

const now = Date.parse("2026-09-07T10:30:00Z");
function fixture(time = now) {
  return {
    host_storage: "observed", storage_control: "read_only", expansion_available: false,
    host_observation: {
      observed_at: new Date(time).toISOString(), expires_at: new Date(time + 90_000).toISOString(),
      storage: { status: "observed", capacity_bytes: 12 * 1024 ** 4, encrypted_members: 1, vg_free_bytes: 0,
        growth: { presented_disk_bytes: 12 * 1024 ** 4, unallocated_disk_bytes: 1024 ** 2, required_stages: [] as string[], expansion_needed: false } },
    },
  };
}

describe("read-only host storage observations", () => {
  it("preserves measured zero and false for a fully measured single disk", () => {
    const result = storageObservation(fixture(), false, now);
    expect(result.state).toBe("observed");
    expect(result.expansion).toBe(false);
    expect(result.storage?.vg_free_bytes).toBe(0);
  });

  it("expires the displayed observation even when no new request occurs", () => {
    expect(storageObservation(fixture(), false, now + 90_001).state).toBe("stale");
    expect(storageObservation(fixture(), false, now + 90_001).storage).toBeUndefined();
    expect(storageObservation(fixture(), false, now + 90_001).expansion).toBeNull();
  });

  it("does not display cached host success after refresh fails", () => {
    const result = storageObservation(fixture(), true, now);
    expect(result.state).toBe("unavailable");
    expect(result.storage).toBeUndefined();
    expect(result.expansion).toBeNull();
  });

  it("supports older responses without growth or explicit expiry", () => {
    const value = fixture() as Record<string, any>;
    delete value.host_observation.expires_at;
    delete value.host_observation.storage.growth;
    const result = storageObservation(value, false, now);
    expect(result.state).toBe("observed");
    expect(result.expansion).toBeNull();
    expect(storageObservation(value, false, now + 90_001).state).toBe("stale");
  });

  it("never converts absent, partial, or unavailable growth to a negative measurement", () => {
    for (const growth of [undefined, null, {}, { presented_disk_bytes: 1024 }]) {
      const value = fixture() as Record<string, any>;
      value.host_observation.storage.growth = growth;
      expect(storageObservation(value, false, now).expansion).toBeNull();
    }
    expect(storageObservation({ host_storage: "unavailable" }, false, now).expansion).toBeNull();
    expect(storageObservation({ host_storage: "not_connected" }, false, now).state).toBe("not_connected");
  });

  it("rejects future or invalid expiry and never extends the host lifetime", () => {
    expect(storageObservation(fixture(now + 5_001), false, now).state).toBe("unavailable");
    const value = fixture();
    value.host_observation.expires_at = "invalid";
    expect(storageObservation(value, false, now).state).toBe("unavailable");
    value.host_observation.expires_at = new Date(now + 3600_000).toISOString();
    expect(storageObservation(value, false, now + 90_001).state).toBe("stale");
  });

  it("keeps additional-disk growth unknown while allowing a measured pool expansion", () => {
    const value = fixture();
    value.host_observation.storage.encrypted_members = 2;
    value.host_observation.storage.growth.presented_disk_bytes = 8 * 1024 ** 4;
    expect(storageObservation(value, false, now).expansion).toBeNull();
    expect(storageObservation(value, false, now).storage?.capacity_bytes).toBe(12 * 1024 ** 4);
    value.host_observation.storage.growth.required_stages = ["lv", "xfs"];
    value.host_observation.storage.growth.expansion_needed = true;
    expect(storageObservation(value, false, now).expansion).toBe(true);
  });

  it("renders readable capacities, explicit disk scope and no execution control", () => {
    const value = fixture(Date.now());
    value.host_observation.storage.encrypted_members = 2;
    value.host_observation.storage.growth.presented_disk_bytes = 8 * 1024 ** 4;
    const html = renderToStaticMarkup(<HostStorageObservation value={value} />);
    expect(html).toContain("12 TiB");
    expect(html).toContain("8 TiB");
    expect(html).toContain("0 B");
    expect(html).toContain("1 MiB");
    expect(html).toContain("Designated disk capacity");
    expect(html).toContain("Additional disk growth has not been measured");
    expect(html).not.toContain("<button");
  });

  it("keeps usable capacity separate from the filesystem journal and volume span", () => {
    const value = fixture(Date.now()) as Record<string, any>;
    value.host_observation.storage.filesystem_geometry_bytes = 13 * 1024 ** 4;
    value.host_observation.storage.logical_volume_bytes = 14 * 1024 ** 4;
    const html = renderToStaticMarkup(<HostStorageObservation value={value} />);
    expect(html).toContain("Usable data pool capacity</dt><dd>12 TiB");
    expect(html).toContain("Filesystem span (includes journal)</dt><dd>13 TiB");
    expect(html).toContain("Logical volume size</dt><dd>14 TiB");
  });
});
