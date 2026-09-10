import { useEffect, useState } from "react";
import type { ReactNode } from "react";

const maxAge = 90_000;

export function observationVisibility(value: Record<string, unknown>, failed: boolean, now: number) {
  if (failed) return { visible: false, message: "Refresh failed. Previous host measurements are no longer shown as current." };
  // These responses explicitly report that the host is unmeasured. Preserve
  // their explanation, without inventing an observation or expiry timestamp.
  if (value.status === "unavailable" || value.status === "not_connected") return { visible: true, message: "" };
  const observed = typeof value.observed_at === "string" ? Date.parse(value.observed_at) : NaN;
  const expiry = value.expires_at === undefined ? observed + maxAge
    : typeof value.expires_at === "string" ? Date.parse(value.expires_at) : NaN;
  if (value.status !== "observed" || !Number.isFinite(observed) || !Number.isFinite(expiry) || expiry < observed || observed > now + 5_000) {
    return { visible: false, message: "Host measurements are incomplete or unavailable. Refresh to request current evidence." };
  }
  if (now > Math.min(expiry, observed + maxAge)) {
    return { visible: false, message: "This host observation has expired. Refresh to request current measurements." };
  }
  return { visible: true, message: "" };
}

export function FreshHostObservation({ value, refreshFailed, children }: {
  value: Record<string, unknown>;
  refreshFailed: boolean;
  children: ReactNode;
}) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const update = () => setNow(Date.now());
    const timer = window.setInterval(update, 1_000);
    document.addEventListener("visibilitychange", update);
    window.addEventListener("focus", update);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", update);
      window.removeEventListener("focus", update);
    };
  }, []);
  const observation = observationVisibility(value, refreshFailed, now);
  return observation.visible ? children : <p className="notice" role="status">{observation.message}</p>;
}
