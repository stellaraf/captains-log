import { describe, it, expect } from "vitest";
import {
  buildClause,
  combine,
  csvCell,
  visibleCSV,
  rangeBounds,
  bytes,
  formatNumber,
  timestamp,
} from "./utils";
import type { EventRecord } from "./types";
describe("PAN-OS filter construction", () => {
  it("preserves operator precedence when adding a clause", () =>
    expect(
      combine(
        "( app eq ssl ) or ( app eq dns )",
        buildClause("port.dst", "eq", "443"),
      ),
    ).toBe('(( app eq ssl ) or ( app eq dns )) and ( port.dst eq "443" )'));
  it("quotes control characters and embedded quotes rather than introducing clauses", () =>
    expect(buildClause("rule", "eq", 'a") or (action eq allow\n')).toBe(
      '( rule eq "a\\\") or (action eq allow\\n" )',
    ));
  it("negates the entire added expression", () =>
    expect(buildClause("addr.src", "in", "2001:db8::/32", true)).toBe(
      'not ( addr.src in "2001:db8::/32" )',
    ));
});
describe("CSV exports", () => {
  it("escapes quoted multiline content", () =>
    expect(csvCell('first,"second"\nthird')).toBe('"first,""second""\nthird"'));
  it.each([
    "=1+1",
    "+SUM(A1:A2)",
    "-42",
    "@SUM(1,2)",
    '  =HYPERLINK("x")',
    "\tcmd",
  ])("neutralizes spreadsheet formula %s", (value) =>
    expect(csvCell(value)).toMatch(/^"'/),
  );
  it("exports selected fields only without losing IPv6", () => {
    const row = {
      id: "one",
      received_at: "2026-09-07T00:00:00Z",
      log_type: "traffic",
      raw: "private",
      src_ip: "2001:db8::1",
      dst_ip: "192.0.2.1",
    } as EventRecord;
    expect(visibleCSV([row], ["src_ip", "dst_ip"])).toBe(
      '\uFEFF"src_ip","dst_ip"\r\n"2001:db8::1","192.0.2.1"\r\n',
    );
  });
});
describe("measured presentation", () => {
  it("formats ClickHouse UInt64 JSON strings", () =>
    expect(formatNumber("100001")).toBe("100,001"));
  it("formats ClickHouse byte counter strings", () =>
    expect(bytes("1024")).toBe("1 KiB"));
  it("interprets timezone-less ClickHouse timestamps as UTC", () =>
    expect(timestamp("2026-09-07 15:00:00.000000")).toBe(
      timestamp("2026-09-07T15:00:00.000Z"),
    ));
  it("does not fabricate unknown storage", () => expect(bytes(null)).toBe("—"));
  it("uses actual range duration", () => {
    const r = rangeBounds("24h");
    expect(Date.parse(r.to) - Date.parse(r.from)).toBe(86400000);
  });
});
