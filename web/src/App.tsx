import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDownUp,
  Bell,
  BookOpen,
  ChevronRight,
  Database,
  FileText,
  Fingerprint,
  Globe2,
  HardDrive,
  HelpCircle,
  KeyRound,
  Layers,
  LockKeyhole,
  LogOut,
  Menu,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Radio,
  Search,
  Server,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Star,
  Terminal,
  UploadCloud,
  UserRound,
  Users,
  X,
} from "lucide-react";
import { api, json, signOut } from "./api";
import { families } from "./types";
import type { Config, Stats, User } from "./types";
import { formatNumber } from "./utils";
import { LogView } from "./LogView";
import { Admin } from "./Admin";
import { EventDetail } from "./EventDetail";
import { Authentication } from "./Authentication";
import { ErrorNotice, Loading } from "./components";
import {
  applyPreferences,
  PreferencesContext,
  readPreferences,
} from "./preferences";
import type { Preferences } from "./preferences";
function usePath() {
  const [path, setPath] = useState(location.pathname + location.search);
  useEffect(() => {
    const fn = () => setPath(location.pathname + location.search);
    addEventListener("popstate", fn);
    return () => removeEventListener("popstate", fn);
  }, []);
  return [
    path,
    (next: string) => {
      history.pushState({}, "", next);
      setPath(location.pathname + location.search);
    },
  ] as const;
}
const familyIcons = [
  ArrowDownUp,
  ShieldAlert,
  Globe2,
  Shield,
  Network,
  Database,
  Fingerprint,
  Globe2,
  Radio,
  Users,
  LockKeyhole,
  Network,
  Settings2,
  Terminal,
  Bell,
  KeyRound,
  Layers,
];
export function App({ config }: { config: Config }) {
  const [route, navigate] = usePath();
  const path = new URL(route, location.origin).pathname;
  const [user, setUser] = useState<User>();
  const [stats, setStats] = useState<Stats>();
  const [statsChecked, setStatsChecked] = useState(false);
  const [error, setError] = useState("");
  const [savedOpen, setSavedOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const navigationRef = useRef<HTMLElement>(null);
  const mobileToggleRef = useRef<HTMLButtonElement>(null);
  const [preferences, setPreferences] = useState(readPreferences);
  const [savingPreference, setSavingPreference] = useState(false);
  const [preferencesReady, setPreferencesReady] = useState(false);
  useEffect(() => {
    api<User>("/api/me")
      .then(setUser)
      .catch((e) => setError(e.message));
    api<Preferences>("/api/preferences")
      .then(setPreferences)
      .catch((e) =>
        setError(`Could not load appearance preferences. ${e.message}`),
      )
      .finally(() => setPreferencesReady(true));
  }, []);
  useEffect(() => {
    applyPreferences(preferences);
    const media = matchMedia("(prefers-color-scheme: dark)");
    const update = () => applyPreferences(preferences);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, [preferences]);
  async function updatePreferences(next: Preferences) {
    const previous = preferences;
    setPreferences(next);
    setSavingPreference(true);
    try {
      await api("/api/preferences", json("PUT", next));
    } catch (e) {
      setPreferences(previous);
      setError(`Appearance was not saved. ${(e as Error).message}`);
    } finally {
      setSavingPreference(false);
    }
  }
  useEffect(() => {
    let cancelled = false;
    const load = () =>
      api<Stats>("/api/stats")
        .then((s) => {
          if (!cancelled) {
            setStats(s);
            setStatsChecked(true);
          }
        })
        .catch(() => {
          if (!cancelled) {
            setStats(undefined);
            setStatsChecked(true);
          }
        });
    void load();
    const timer = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);
  useEffect(() => {
    setMobileOpen(false);
  }, [route]);
  useEffect(() => {
    if (mobileOpen)
      navigationRef.current
        ?.querySelector<HTMLButtonElement>(".rail-mobile-close")
        ?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (!mobileOpen) return;
      if (e.key === "Escape") {
        setMobileOpen(false);
        mobileToggleRef.current?.focus();
      }
      if (e.key === "Tab") {
        const items = [
          ...(navigationRef.current?.querySelectorAll<HTMLElement>(
            "a[href],button:not(:disabled)",
          ) || []),
        ].filter((el) => el.getBoundingClientRect().width > 0);
        const first = items[0],
          last = items[items.length - 1];
        if (!first || !last) return;
        if (
          e.shiftKey &&
          (document.activeElement === first ||
            !navigationRef.current?.contains(document.activeElement))
        ) {
          e.preventDefault();
          last.focus();
        } else if (
          !e.shiftKey &&
          (document.activeElement === last ||
            !navigationRef.current?.contains(document.activeElement))
        ) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, [mobileOpen]);
  const admin = path.startsWith("/administration/");
  const section = admin ? path.split("/")[2] || "firewalls" : "logs";
  const type = path.startsWith("/logs/") ? path.split("/")[2] : "traffic";
  const eventId =
    !admin && path.split("/")[3] === "events" ? path.split("/")[4] : undefined;
  const firewallSerial =
    admin && section === "firewalls" ? path.split("/")[3] : undefined;
  const validType = families.some((f) => f[0] === type) || type === "parsing";
  const title = eventId
    ? "Event details"
    : firewallSerial
      ? "Firewall details"
      : admin
        ? {
            firewalls: "Firewalls",
            storage: "Storage & retention",
            diagnostics: "Syslog diagnostics",
            security: "Security & compliance",
            updates: "System updates",
            setup: "Firewall setup",
            authentication: "Authentication",
          }[section] || "Administration"
        : type === "parsing"
          ? "Parsing diagnostics"
          : families.find((f) => f[0] === type)?.[1] || "Traffic";
  useEffect(() => {
    document.title = `${title} · Captain’s Log · Stellar`;
  }, [title]);
  const navItems = [
    ["firewalls", "Firewalls", Server],
    ["storage", "Storage & retention", HardDrive],
    ["diagnostics", "Diagnostics", Terminal],
    ["authentication", "Authentication", KeyRound],
    ["security", "Security & compliance", ShieldCheck],
    ["updates", "System updates", UploadCloud],
    ["setup", "Firewall setup", HelpCircle],
  ] as const;
  const follow = (e: React.MouseEvent<HTMLAnchorElement>, next: string) => {
    if (!e.metaKey && !e.ctrlKey && !e.shiftKey && e.button === 0) {
      e.preventDefault();
      navigate(next);
    }
  };
  return (
    <PreferencesContext.Provider value={preferences}>
      <div
        className={`app-shell ${preferences.rail_collapsed ? "rail-collapsed" : ""} ${mobileOpen ? "mobile-nav-open" : ""}`}
      >
        <a className="skip-link" href="#main-content">
          Skip to main content
        </a>
        <header className="topbar">
          <div className="topbar-identity">
            <button
              ref={mobileToggleRef}
              className="icon-button mobile-menu"
              aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
              aria-expanded={mobileOpen}
              aria-controls="primary-navigation"
              onClick={() => setMobileOpen(!mobileOpen)}
            >
              {mobileOpen ? <X size={19} /> : <Menu size={19} />}
            </button>
            <a
              href="/logs/traffic"
              className="stellar-brand"
              onClick={(e) => follow(e, "/logs/traffic")}
              aria-label="Stellar Captain’s Log home"
            >
              <img src="/brand/stellar-logo-gradient.png" alt="Stellar" />
            </a>
            <span className="identity-divider" />
            <div className="app-identity">
              <strong>Captain’s Log</strong>
              <span>Security operations</span>
            </div>
            <span className="workspace-context">
              <Server size={13} /> Local appliance
            </span>
          </div>
          <div className="global-utilities">
            <label className="appearance-control">
              <span>Theme</span>
              <select
                aria-label="Theme"
                value={preferences.theme}
                disabled={savingPreference || !preferencesReady}
                onChange={(e) =>
                  void updatePreferences({
                    ...preferences,
                    theme: e.target.value as Preferences["theme"],
                  })
                }
              >
                <option value="dark">Dark</option>
                <option value="light">Light</option>
                <option value="system">System</option>
              </select>
            </label>
            <label className="appearance-control density-control">
              <span>Density</span>
              <select
                aria-label="Density"
                value={preferences.density}
                disabled={savingPreference || !preferencesReady}
                onChange={(e) =>
                  void updatePreferences({
                    ...preferences,
                    density: e.target.value as Preferences["density"],
                  })
                }
              >
                <option value="compact">Compact</option>
                <option value="comfortable">Comfortable</option>
              </select>
            </label>
            <div className="user-menu">
              <span className="avatar">
                <UserRound size={15} />
              </span>
              <span className="account-identity">
                {user?.name || "Loading account"}
                <small>{user?.role.toLowerCase()}</small>
              </span>
              <button
                className="icon-button"
                aria-label="Sign out"
                title="Sign out"
                onClick={() => void signOut()}
              >
                <LogOut size={16} />
              </button>
            </div>
          </div>
        </header>
        {mobileOpen && (
          <button
            className="nav-backdrop"
            aria-label="Close navigation overlay"
            onClick={() => setMobileOpen(false)}
          />
        )}
        <aside
          ref={navigationRef}
          role={mobileOpen ? "dialog" : undefined}
          aria-modal={mobileOpen || undefined}
          className="sidebar"
          id="primary-navigation"
          aria-label="Primary navigation"
        >
          <div className="rail-context">
            <button
              className="icon-button rail-mobile-close"
              aria-label="Close navigation"
              onClick={() => {
                setMobileOpen(false);
                mobileToggleRef.current?.focus();
              }}
            >
              <X size={18} />
            </button>
            <img src="/brand/stellar-icon-gradient.png" alt="" />
            <div>
              <strong>Captain’s Log</strong>
              <small>Log intelligence</small>
            </div>
            <button
              className="icon-button rail-toggle"
              aria-label={
                preferences.rail_collapsed
                  ? "Expand navigation"
                  : "Collapse navigation"
              }
              title={
                preferences.rail_collapsed
                  ? "Expand navigation"
                  : "Collapse navigation"
              }
              disabled={savingPreference || !preferencesReady}
              onClick={() =>
                void updatePreferences({
                  ...preferences,
                  rail_collapsed: !preferences.rail_collapsed,
                })
              }
            >
              {preferences.rail_collapsed ? (
                <PanelLeftOpen size={16} />
              ) : (
                <PanelLeftClose size={16} />
              )}
            </button>
          </div>
          <div className="nav-overline">
            <FileText size={13} />
            <span>Logs</span>
          </div>
          <nav aria-label="Log categories">
            {families.map(([id, label], i) => {
              const Icon = familyIcons[i];
              return (
                <a
                  key={id}
                  title={label}
                  href={`/logs/${id}`}
                  className={
                    !admin && type === id ? "nav-link active" : "nav-link"
                  }
                  aria-current={!admin && type === id ? "page" : undefined}
                  onClick={(e) => follow(e, `/logs/${id}`)}
                >
                  <Icon size={15} />
                  <span>{label}</span>
                </a>
              );
            })}
          </nav>
          <button
            className="nav-link saved-nav"
            title="Saved filters"
            onClick={() => {
              if (admin || eventId) navigate("/logs/traffic");
              setSavedOpen(true);
            }}
          >
            <Star size={15} />
            <span>Saved filters</span>
          </button>
          <div className="nav-overline admin-overline">
            <SlidersHorizontal size={13} />
            <span>Administration</span>
          </div>
          <nav aria-label="Administration">
            {navItems.map(([id, label, Icon]) => (
              <a
                key={id}
                href={`/administration/${id}`}
                title={label}
                onClick={(e) => follow(e, `/administration/${id}`)}
                className={
                  admin && section === id ? "nav-link active" : "nav-link"
                }
                aria-current={admin && section === id ? "page" : undefined}
              >
                <Icon size={15} />
                <span>{label}</span>
              </a>
            ))}
          </nav>
          <div className="sidebar-foot">
            <span
              className={stats ? "connection connected" : "connection"}
              title={
                stats
                  ? "API connected"
                  : statsChecked
                    ? "API unavailable"
                    : "Connecting to API"
              }
            >
              <i />
              <span>
                {stats
                  ? "API connected"
                  : statsChecked
                    ? "API unavailable"
                    : "Connecting"}
              </span>
            </span>
            <span className="version">v{config.version}</span>
          </div>
        </aside>
        <main className="workspace" id="main-content" tabIndex={-1}>
          <div className="page-head">
            <div>
              <div className="breadcrumbs">
                <span>{admin ? "Administration" : "Log explorer"}</span>
                <ChevronRight size={12} />
                <span>{title}</span>
              </div>
              <h1>{title}</h1>
            </div>
            {!admin && !eventId && (
              <div className="ingest-summary">
                <Activity size={15} />
                <strong>{formatNumber(stats?.events_per_second)}</strong>
                <span>events / sec</span>
                <div className="summary-divider" />
                <span>Queue</span>
                <strong>{formatNumber(stats?.queue_depth)}</strong>
              </div>
            )}
          </div>
          {error && (
            <ErrorNotice>
              {error}
              <button onClick={() => setError("")}>Dismiss</button>
            </ErrorNotice>
          )}
          {!user ? (
            <Loading label="Verifying your access…" />
          ) : eventId ? (
            <EventDetail key={eventId} id={eventId} navigate={navigate} />
          ) : admin ? (
            section === "authentication" ? (
              <Authentication config={config} user={user} />
            ) : (
              <Admin
                section={section}
                serial={firewallSerial}
                user={user}
                navigate={navigate}
              />
            )
          ) : validType ? (
            <LogView
              key={type}
              type={type}
              user={user}
              stats={stats}
              savedOpen={savedOpen}
              closeSaved={() => setSavedOpen(false)}
              navigate={navigate}
            />
          ) : (
            <div className="notice">
              Unknown log category.{" "}
              <button onClick={() => navigate("/logs/traffic")}>
                Open Traffic
              </button>
            </div>
          )}
          <footer className="workspace-foot">
            <span>
              <Search size={12} /> PAN-OS log collection & search
            </span>
            <a
              href="/administration/setup"
              onClick={(e) => follow(e, "/administration/setup")}
            >
              <BookOpen size={12} /> Forwarding guide
            </a>
          </footer>
        </main>
      </div>
    </PreferencesContext.Provider>
  );
}
