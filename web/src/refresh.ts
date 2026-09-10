export const refreshIntervals = [0, 5, 10, 30, 60] as const;
export interface RefreshPreferences {
  intervalSeconds: number;
  paused: boolean;
}
const defaults: RefreshPreferences = { intervalSeconds: 10, paused: false };

function key(userId: string) {
  return `nebulalog.refresh.${encodeURIComponent(userId)}`;
}

export function readRefreshPreferences(userId: string): RefreshPreferences {
  try {
    const stored = JSON.parse(localStorage.getItem(key(userId)) || "null");
    return {
      intervalSeconds: refreshIntervals.some((n) => n === stored?.intervalSeconds)
        ? stored.intervalSeconds
        : defaults.intervalSeconds,
      paused: stored?.paused === true,
    };
  } catch {
    return { ...defaults };
  }
}

export function writeRefreshPreferences(userId: string, value: RefreshPreferences) {
  try {
    localStorage.setItem(key(userId), JSON.stringify(value));
  } catch {
    // Refresh still works when browser storage is unavailable.
  }
}
