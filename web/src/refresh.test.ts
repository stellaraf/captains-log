import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readRefreshPreferences, writeRefreshPreferences } from "./refresh";

describe("account-scoped refresh preferences", () => {
  let values: Map<string, string>;
  beforeEach(() => {
    values = new Map();
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
    });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("restores an interval and pause state without changing another account", () => {
    writeRefreshPreferences("analyst/one", { intervalSeconds: 30, paused: true });
    expect(readRefreshPreferences("analyst/one")).toEqual({ intervalSeconds: 30, paused: true });
    expect(readRefreshPreferences("analyst/two")).toEqual({ intervalSeconds: 10, paused: false });
  });

  it("preserves manual refresh mode", () => {
    writeRefreshPreferences("one", { intervalSeconds: 0, paused: false });
    expect(readRefreshPreferences("one")).toEqual({ intervalSeconds: 0, paused: false });
  });

  it("rejects corrupt data and intervals that could overload the appliance", () => {
    values.set("nebulalog.refresh.one", "not-json");
    expect(readRefreshPreferences("one").intervalSeconds).toBe(10);
    values.set("nebulalog.refresh.one", '{"intervalSeconds":0.001,"paused":"false"}');
    expect(readRefreshPreferences("one")).toEqual({ intervalSeconds: 10, paused: false });
  });

  it("continues to work when browser storage is blocked", () => {
    vi.stubGlobal("localStorage", {
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
    });
    expect(readRefreshPreferences("one")).toEqual({ intervalSeconds: 10, paused: false });
    expect(() => writeRefreshPreferences("one", { intervalSeconds: 60, paused: true })).not.toThrow();
  });
});
