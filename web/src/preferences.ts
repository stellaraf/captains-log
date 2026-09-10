import { createContext, useContext } from "react";
export interface Preferences {
  theme: "dark" | "light" | "system";
  density: "compact" | "comfortable";
  rail_collapsed: boolean;
}
export const defaultPreferences: Preferences = {
  theme: "system",
  density: "compact",
  rail_collapsed: false,
};
export function readPreferences(): Preferences {
  try {
    const p = JSON.parse(
      localStorage.getItem("nebulalog.appearance") || "null",
    );
    return {
      theme: ["light", "dark", "system"].includes(p?.theme)
        ? p.theme
        : "system",
      density: p?.density === "comfortable" ? "comfortable" : "compact",
      rail_collapsed: p?.rail_collapsed === true,
    };
  } catch {
    return defaultPreferences;
  }
}
export function applyPreferences(p: Preferences) {
  const theme =
    p.theme === "system"
      ? matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light"
      : p.theme;
  document.documentElement.dataset.theme = theme;
  document.documentElement.dataset.density = p.density;
  try {
    localStorage.setItem("nebulalog.appearance", JSON.stringify(p));
  } catch {
    /* Account preferences remain authoritative. */
  }
}
export const PreferencesContext = createContext(defaultPreferences);
export function usePreferences() {
  return useContext(PreferencesContext);
}
