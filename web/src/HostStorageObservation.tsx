import { useEffect, useState } from "react";
import { bytes, formatNumber, timestamp } from "./utils";

const maxAge = 90_000;
const stages = ["partition", "luks", "pv", "lv", "xfs"];
const stageNames: Record<string, string> = {
  partition: "Data partition",
  luks: "Encrypted mapping",
  pv: "Physical volume",
  lv: "Logical volume",
  xfs: "Filesystem",
};

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function count(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && Number.isInteger(value);
}

export function storageObservation(value: Record<string, unknown>, refreshFailed: boolean, now: number) {
  const observation = record(value.host_observation);
  const observedAt = typeof observation?.observed_at === "string" ? observation.observed_at : undefined;
  const observed = observedAt ? Date.parse(observedAt) : NaN;
  const declaredExpiry = observation?.expires_at === undefined
    ? observed + maxAge // Older API responses did not include an explicit expiry.
    : typeof observation.expires_at === "string" ? Date.parse(observation.expires_at) : NaN;
  const expires = Math.min(declaredExpiry, observed + maxAge);
  const storage = record(observation?.storage);
  const empty = { observedAt, storage: undefined, growth: undefined, expansion: null, additionalDisks: false };
  if (refreshFailed) return { ...empty, state: "unavailable", message: "Refresh failed. Previous host storage measurements are not current." };
  if (value.host_storage === "not_connected") return { ...empty, state: "not_connected", message: "Host storage observations are not connected to this deployment." };
  if (value.host_storage !== "observed" || !Number.isFinite(observed) || !Number.isFinite(expires) || expires < observed || observed > now + 5_000 || storage?.status !== "observed") {
    return { ...empty, state: "unavailable", message: "Host storage measurements are unavailable. Refresh after the status publisher recovers." };
  }
  if (now > expires) return { ...empty, state: "stale", message: "This host storage observation has expired. Refresh to obtain current measurements." };
  if (!count(storage.capacity_bytes) || storage.capacity_bytes === 0 || !count(storage.encrypted_members) || storage.encrypted_members === 0 || !count(storage.vg_free_bytes)) {
    return { ...empty, state: "unavailable", message: "Host storage measurements are incomplete. Refresh after the status publisher recovers." };
  }
  const candidate = record(storage.growth);
  const required = candidate?.required_stages;
  const validGrowth = candidate && count(candidate.presented_disk_bytes) && candidate.presented_disk_bytes > 0
    && count(candidate.unallocated_disk_bytes) && candidate.unallocated_disk_bytes <= candidate.presented_disk_bytes
    && typeof candidate.expansion_needed === "boolean" && Array.isArray(required) && required.length <= stages.length
    && candidate.expansion_needed === (required.length > 0)
    && required.every((stage, index) => stage === stages[stages.length - required.length + index]);
  const growth = validGrowth ? candidate : undefined;
  const additionalDisks = storage.encrypted_members > 1;
  // The old API could report false for a multi-PV pool after inspecting only
  // its designated disk. Preserve unknown until every disk's geometry is measured.
  const expansion = growth ? growth.expansion_needed === true ? true : additionalDisks ? null : false : null;
  return { observedAt, storage, growth, expansion, additionalDisks, state: "observed",
    message: "Read-only host measurements. Storage changes are not available in this browser." };
}

export function HostStorageObservation({ value, refreshFailed = false }: { value: Record<string, unknown>; refreshFailed?: boolean }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const refreshClock = () => setNow(Date.now());
    const timer = window.setInterval(refreshClock, 1_000);
    document.addEventListener("visibilitychange", refreshClock);
    window.addEventListener("focus", refreshClock);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshClock);
      window.removeEventListener("focus", refreshClock);
    };
  }, []);
  const observation = storageObservation(value, refreshFailed, now);
  const { storage, growth } = observation;
  const rows: [string, string][] = [["Observation", observation.state === "observed" ? "Current" : observation.state === "stale" ? "Expired" : observation.state === "not_connected" ? "Not connected" : "Unavailable"]];
  if (observation.observedAt) rows.push(["Measured at", timestamp(observation.observedAt)]);
  if (storage) {
    rows.push(["Usable data pool capacity", bytes(storage.capacity_bytes)], ["Unallocated space in pool", bytes(storage.vg_free_bytes)],
      ["Encrypted pool members", formatNumber(storage.encrypted_members)],
      ["Expansion detected", observation.expansion === null ? "Unknown" : observation.expansion ? "Yes" : "No"]);
    if (count(storage.filesystem_geometry_bytes) && count(storage.logical_volume_bytes)) {
      rows.push(["Filesystem span (includes journal)", bytes(storage.filesystem_geometry_bytes)], ["Logical volume size", bytes(storage.logical_volume_bytes)]);
    }
  }
  if (growth) {
    rows.push(["Growth scope", "Designated disk and unallocated pool space"],
      ["Designated disk capacity", bytes(growth.presented_disk_bytes)],
      ["Unallocated on designated disk", bytes(growth.unallocated_disk_bytes)],
      ["Required host stages", (growth.required_stages as string[]).map((stage) => stageNames[stage]).join(" → ") || "None within measured scope"]);
  }
  return <>
    <p className="notice" role="status">{observation.message}</p>
    <dl className="observed-values">{rows.map(([name, content]) => <div key={name}><dt>{name}</dt><dd>{content}</dd></div>)}</dl>
    {storage && observation.additionalDisks && <p className="muted">Additional disk growth has not been measured. Pool capacity can exceed the designated disk capacity.</p>}
    {storage && !growth && <p className="muted">Disk growth was not reported; expansion availability remains unknown.</p>}
  </>;
}
