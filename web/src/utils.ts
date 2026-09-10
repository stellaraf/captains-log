import type { EventRecord } from "./types";
function numeric(v: unknown): number | null {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string" && /^\d+(\.\d+)?$/.test(v)) {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}
export const formatNumber = (v: unknown) =>
  numeric(v) === null
    ? "—"
    : new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 }).format(
        numeric(v)!,
      );
export function bytes(input: unknown) {
  const v = numeric(input);
  if (v === null || v < 0) return "—";
  if (v === 0) return "0 B";
  const i = Math.min(4, Math.max(0, Math.floor(Math.log(v) / Math.log(1024))));
  return `${new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 }).format(v / 1024 ** i)} ${["B", "KiB", "MiB", "GiB", "TiB"][i]}`;
}
export function timestamp(v: unknown) {
  if (typeof v !== "string" || !v) return "—";
  const utc = /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?$/.test(v)
    ? `${v.replace(" ", "T")}Z`
    : v;
  const d = new Date(utc);
  return Number.isNaN(d.valueOf())
    ? v
    : d.toLocaleString("en-CA", { hour12: false });
}
export function quoteValue(v: unknown) {
  return JSON.stringify(String(v ?? ""));
}
export function combine(query: string, clause: string, connector = "and") {
  return query.trim() ? `(${query.trim()}) ${connector} ${clause}` : clause;
}
export function buildClause(
  alias: string,
  operator: string,
  value: string,
  negate = false,
) {
  const clause = `( ${alias} ${operator} ${quoteValue(value)} )`;
  return negate ? `not ${clause}` : clause;
}
export function csvCell(value: unknown) {
  let str = String(value ?? "");
  if (/^[\s]*[=+@\-\t\r]/.test(str)) str = `'${str}`;
  return `"${str.replaceAll('"', '""')}"`;
}
export function visibleCSV(events: EventRecord[], selected: string[]) {
  return (
    "\uFEFF" +
    [
      selected.map(csvCell).join(","),
      ...events.map((event) =>
        selected.map((column) => csvCell(event[column])).join(","),
      ),
    ].join("\r\n") +
    "\r\n"
  );
}
export function rangeBounds(range: string) {
  const to = new Date();
  const durations: Record<string, number> = {
    "15m": 15 * 60e3,
    "1h": 3600e3,
    "6h": 6 * 3600e3,
    "24h": 24 * 3600e3,
    "7d": 7 * 24 * 3600e3,
    "30d": 30 * 24 * 3600e3,
  };
  return {
    from: new Date(
      to.valueOf() - (durations[range] ?? durations["1h"]),
    ).toISOString(),
    to: to.toISOString(),
  };
}
