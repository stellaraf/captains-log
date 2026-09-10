import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  Database,
  HardDrive,
  RefreshCw,
  Server,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { api, json } from "./api";
import { families } from "./types";
import type { Firewall, Stats, Storage, User } from "./types";
import { bytes, formatNumber, timestamp } from "./utils";
import { Empty, ErrorNotice, Loading, Status } from "./components";
import { categoryGuidance } from "./LogCategoryHelp";
import { HostStorageObservation } from "./HostStorageObservation";
import { HostStoragePlan } from "./HostStoragePlan";
import { FreshHostObservation } from "./FreshHostObservation";
import { SyslogTLSCertificate } from "./SyslogTLSCertificate";
function useData<T>(path: string) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(true);
  const [refreshFailed, setRefreshFailed] = useState(false);
  const request = useRef(0);
  const controller = useRef<AbortController | undefined>(undefined);
  const load = useCallback(async () => {
    const current = ++request.current;
    controller.current?.abort();
    const active = new AbortController();
    controller.current = active;
    setBusy(true);
    setError("");
    try {
      const value = await api<T>(path, { signal: active.signal });
      if (current !== request.current) return;
      setData(value);
      setRefreshFailed(false);
    } catch (e) {
      if (current !== request.current || active.signal.aborted) return;
      setError((e as Error).message);
      setRefreshFailed(true);
    } finally {
      if (current === request.current) setBusy(false);
    }
  }, [path]);
  useEffect(() => {
    setData(undefined);
    setError("");
    setRefreshFailed(false);
    void load();
    return () => {
      request.current++;
      controller.current?.abort();
    };
  }, [load]);
  return { data, error, busy, load, refreshFailed };
}
export function Admin({
  section,
  serial,
  user,
  navigate,
}: {
  section: string;
  serial?: string;
  user: User;
  navigate: (path: string) => void;
}) {
  return (
    <div className="admin-workspace">
      {section === "firewalls" ? (
        <Firewalls user={user} serial={serial} navigate={navigate} />
      ) : section === "storage" ? (
        <StoragePage user={user} />
      ) : section === "diagnostics" ? (
        <Diagnostics user={user} navigate={navigate} />
      ) : section === "security" ? (
        <ObservedPage
          key="security"
          path="/api/security"
          title="Security posture"
          icon="security"
          description="Security information reported by this appliance. Unverified host controls remain unverified until measured on the Rocky Linux appliance."
        />
      ) : section === "updates" ? (
        <ObservedPage
          key="updates"
          path="/api/updates"
          title="Update manager"
          icon="updates"
          description="Supported versions and observed update-manager capability. Appliance release and rollback validation are distinct from application availability."
        />
      ) : section === "setup" ? (
        <Setup />
      ) : (
        <Empty title="Page not found">
          <button onClick={() => navigate("/logs/traffic")}>
            Open log explorer
          </button>
        </Empty>
      )}
    </div>
  );
}
function Firewalls({
  user,
  serial,
  navigate,
}: {
  user: User;
  serial?: string;
  navigate: (path: string) => void;
}) {
  const { data, error, busy, load } = useData<{ firewalls: Firewall[] }>(
    "/api/firewalls",
  );
  const [editing, setEditing] = useState<Firewall>();
  const [editError, setEditError] = useState("");
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState("");
  useEffect(() => {
    const target = data?.firewalls.find((f) => f.serial === serial);
    setEditing(target ? { ...target, tags: target.tags || [] } : undefined);
  }, [serial, data]);
  useEffect(() => {
    setNotice("");
    setEditError("");
  }, [serial]);
  const follow = (e: React.MouseEvent<HTMLAnchorElement>, path: string) => {
    if (!e.metaKey && !e.ctrlKey) {
      e.preventDefault();
      navigate(path);
    }
  };
  if (serial)
    return (
      <>
        <a
          className="back-link"
          href="/administration/firewalls"
          onClick={(e) => follow(e, "/administration/firewalls")}
        >
          <ArrowLeft size={15} /> Back to firewalls
        </a>
        {error && <ErrorNotice>{error}</ErrorNotice>}
        {busy && !data ? (
          <Loading />
        ) : !editing ? (
          <Empty title="Firewall not found">
            <p>This serial has not been observed by this appliance.</p>
          </Empty>
        ) : (
          <>
            <div className="resource-heading">
              <span className="resource-icon">
                <Server size={24} />
              </span>
              <div>
                <h2>
                  {editing.friendly_name ||
                    editing.device_name ||
                    "Unnamed firewall"}
                </h2>
                <p className="mono">{editing.serial}</p>
              </div>
              <Status value={editing.status} />
            </div>
            <div className="resource-subtitle">
              <span>{editing.sender_ip}</span>
              <span>Last seen {timestamp(editing.last_seen)}</span>
            </div>
            <nav className="section-tabs" aria-label="Firewall sections">
              <a href="#overview">Overview</a>
              <a href="#inventory">Inventory settings</a>
            </nav>
            <section className="resource-section" id="overview">
              <div className="section-toolbar">
                <div>
                  <h3>Observed activity</h3>
                  <p>Measurements from received syslog events.</p>
                </div>
                <a
                  className="button"
                  href={`/logs/unified?query=${encodeURIComponent(`device eq '${editing.serial}'`)}`}
                  onClick={(e) =>
                    follow(
                      e,
                      `/logs/unified?query=${encodeURIComponent(`device eq '${editing.serial}'`)}`,
                    )
                  }
                >
                  Search firewall logs <ArrowRight size={14} />
                </a>
              </div>
              <dl className="event-details">
                {[
                  ["Serial", editing.serial],
                  ["Device name", editing.device_name || "Unknown"],
                  ["Sender IP", editing.sender_ip],
                  ["PAN-OS version", editing.panos_version || "Unknown"],
                  ["Current EPS", formatNumber(editing.current_eps)],
                  ["Average EPS", formatNumber(editing.average_eps)],
                  ["Peak EPS", formatNumber(editing.peak_eps)],
                  ["Events today", formatNumber(editing.events_today)],
                  ["First seen", timestamp(editing.first_seen)],
                  ["Last seen", timestamp(editing.last_seen)],
                ].map(([label, value]) => (
                  <div key={label}>
                    <dt>{label}</dt>
                    <dd>{value}</dd>
                  </div>
                ))}
              </dl>
            </section>
            <section className="resource-section" id="inventory">
              <div className="section-toolbar">
                <div>
                  <h3>Inventory settings</h3>
                  <p>
                    Friendly labels belong to this appliance. Device identity is
                    observed from the firewall.
                  </p>
                </div>
              </div>
              <form
                className="resource-form"
                onSubmit={async (e) => {
                  e.preventDefault();
                  setSaving(true);
                  setEditError("");
                  setNotice("");
                  try {
                    await api(
                      `/api/firewalls/${encodeURIComponent(editing.serial)}`,
                      json("PUT", {
                        friendly_name: editing.friendly_name,
                        site: editing.site,
                        tags: editing.tags.filter(Boolean),
                        notes: editing.notes,
                      }),
                    );
                    await load();
                    setNotice("Firewall inventory saved.");
                  } catch (err) {
                    setEditError((err as Error).message);
                  } finally {
                    setSaving(false);
                  }
                }}
              >
                <fieldset disabled={user.role !== "ADMINISTRATOR" || saving}>
                  <div className="form-grid">
                    <label>
                      Friendly name
                      <input
                        value={editing.friendly_name || ""}
                        onChange={(e) =>
                          setEditing({
                            ...editing,
                            friendly_name: e.target.value,
                          })
                        }
                      />
                    </label>
                    <label>
                      Site
                      <input
                        value={editing.site || ""}
                        onChange={(e) =>
                          setEditing({ ...editing, site: e.target.value })
                        }
                      />
                    </label>
                  </div>
                  <label>
                    Tags (comma-separated)
                    <input
                      value={editing.tags.join(", ")}
                      onChange={(e) =>
                        setEditing({
                          ...editing,
                          tags: e.target.value.split(",").map((t) => t.trim()),
                        })
                      }
                    />
                  </label>
                  <label>
                    Notes
                    <textarea
                      value={editing.notes || ""}
                      onChange={(e) =>
                        setEditing({ ...editing, notes: e.target.value })
                      }
                    />
                  </label>
                </fieldset>
                {editError && <ErrorNotice>{editError}</ErrorNotice>}
                {notice && (
                  <div className="notice success" role="status">
                    {notice}
                  </div>
                )}
                {user.role === "ADMINISTRATOR" ? (
                  <div className="form-actions">
                    <button className="primary" disabled={saving}>
                      {saving ? "Saving…" : "Save changes"}
                    </button>
                  </div>
                ) : (
                  <p className="muted">
                    An administrator can edit inventory settings.
                  </p>
                )}
              </form>
            </section>
          </>
        )}
      </>
    );
  return (
    <>
      <div className="section-toolbar">
        <div>
          <h2>
            Discovered firewalls{" "}
            <span className="count-tag">{data?.firewalls.length ?? "—"}</span>
          </h2>
          <p>
            Devices appear after this appliance receives their syslog events.
          </p>
        </div>
        <button onClick={() => void load()}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>
      {error && <ErrorNotice>{error}</ErrorNotice>}
      {busy && !data ? (
        <Loading />
      ) : data?.firewalls.length ? (
        <div
          className="panel-table-scroll"
          role="region"
          aria-label="Firewall inventory"
          tabIndex={0}
        >
          <table className="admin-table">
            <thead>
              <tr>
                {[
                  "Firewall",
                  "Serial",
                  "Sender IP",
                  "Site / tags",
                  "PAN-OS",
                  "Current EPS",
                  "Average EPS",
                  "Peak EPS",
                  "Events today",
                  "Last seen",
                  "Status",
                ].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.firewalls.map((f) => (
                <tr key={f.serial}>
                  <td>
                    <a
                      className="resource-link"
                      href={`/administration/firewalls/${encodeURIComponent(f.serial)}`}
                      onClick={(e) =>
                        follow(
                          e,
                          `/administration/firewalls/${encodeURIComponent(f.serial)}`,
                        )
                      }
                    >
                      <Server size={16} />
                      <span>
                        <strong>
                          {f.friendly_name ||
                            f.device_name ||
                            "Unnamed firewall"}
                        </strong>
                        <small>{f.device_name}</small>
                      </span>
                    </a>
                  </td>
                  <td className="mono">{f.serial}</td>
                  <td className="mono">{f.sender_ip}</td>
                  <td>
                    {f.site || "—"}
                    <small>{(f.tags || []).join(", ")}</small>
                  </td>
                  <td>{f.panos_version || "Unknown"}</td>
                  <td>{formatNumber(f.current_eps)}</td>
                  <td>{formatNumber(f.average_eps)}</td>
                  <td>{formatNumber(f.peak_eps)}</td>
                  <td>{formatNumber(f.events_today)}</td>
                  <td>{timestamp(f.last_seen)}</td>
                  <td>
                    <Status value={f.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty title="No firewalls discovered">
          <p>
            Configure a syslog server profile and attach a log forwarding
            profile to your firewall’s security rules.
          </p>
          <a href="/administration/setup">
            View forwarding instructions <ArrowRight size={13} />
          </a>
        </Empty>
      )}
    </>
  );
}
function StoragePage({ user }: { user: User }) {
  const storage = useData<Storage>("/api/storage");
  const retention = useData<{
    global_days: number;
    per_type: Record<string, number>;
  }>("/api/retention");
  const [policy, setPolicy] = useState<{
    global_days: number;
    per_type: Record<string, number>;
  }>();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (retention.data) setPolicy(retention.data);
  }, [retention.data]);
  const data = storage.data;
  const utilization = data?.capacity_bytes
    ? (data.used_bytes / data.capacity_bytes) * 100
    : null;
  return (
    <>
      <div className="section-toolbar">
        <div>
          <h2>
            <HardDrive size={18} /> Data storage
          </h2>
          <p>
            Capacity and projections use measured database storage. Unknown
            projections are not estimated.
          </p>
        </div>
        <button
          onClick={() => {
            void storage.load();
            void retention.load();
          }}
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>
      {storage.error && <ErrorNotice>{storage.error}</ErrorNotice>}
      {data ? (
        <>
          <section className="storage-overview">
            <div className="capacity-main">
              <span>USED CAPACITY</span>
              <strong>
                {bytes(data.used_bytes)}
                <small> / {bytes(data.capacity_bytes)}</small>
              </strong>
              <div className="capacity-meter">
                <span
                  style={{ width: `${Math.min(100, utilization ?? 0)}%` }}
                  className={(utilization || 0) >= 90 ? "critical" : ""}
                />
                <i style={{ left: `${100 - (data.reserve_percent || 15)}%` }} />
              </div>
              <div className="capacity-labels">
                <span>
                  {utilization === null
                    ? "Unknown"
                    : `${utilization.toFixed(1)}% used`}
                </span>
                <span>{data.reserve_percent ?? 15}% operational reserve</span>
              </div>
            </div>
            <div className="storage-measures">
              <div>
                <span>Available</span>
                <strong>{bytes(data.available_bytes)}</strong>
              </div>
              <div>
                <span>Log database</span>
                <strong>{bytes(data.database_bytes)}</strong>
              </div>
              <div>
                <span>Retained events</span>
                <strong>{formatNumber(data.events)}</strong>
              </div>
              <div>
                <span>Measured bytes / event</span>
                <strong>
                  {data.bytes_per_event === null
                    ? "Not enough data"
                    : bytes(data.bytes_per_event)}
                </strong>
              </div>
              <div>
                <span>Growth / day</span>
                <strong>
                  {data.daily_growth_bytes === null
                    ? "Not enough data"
                    : bytes(data.daily_growth_bytes)}
                </strong>
              </div>
              <div>
                <span>Estimated retention</span>
                <strong>
                  {data.estimated_retention_days === null
                    ? "Not enough data"
                    : `${formatNumber(data.estimated_retention_days)} days`}
                </strong>
              </div>
            </div>
          </section>
          <div className="section-toolbar small">
            <h3>Capacity requirements</h3>
            <Status value={data.status} />
          </div>
          {data.requirements?.length ? (
            <div className="requirements">
              {data.requirements.map((r, i) => {
                const v = r as Record<string, unknown>;
                return (
                  <div key={i}>
                    <span>{String(v.days ?? v.retention_days ?? "")} days</span>
                    <strong>
                      {bytes(
                        v.recommended_bytes ??
                          v.required_bytes ??
                          v.capacity_bytes ??
                          v.bytes,
                      )}
                    </strong>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="notice">
              Storage sizing will become available after sufficient real
              database-growth measurements have been collected.
            </div>
          )}
          <section className="panel">
            <h3>Host storage integration</h3>
            <HostStorageObservation
              value={data}
              refreshFailed={storage.refreshFailed}
            />
            <ObservedValues
              value={{
                measurement: data.measurement,
                emergency_policy: data.emergency_policy,
                days_until_full: data.days_until_full,
              }}
            />
          </section>
        </>
      ) : storage.busy ? (
        <Loading />
      ) : null}
      <HostStoragePlan user={user} />
      <section className="retention-section">
        <div className="section-toolbar">
          <div>
            <h2>Retention policy</h2>
            <p>
              Changes apply to new arrivals. Existing events retain their
              assigned expiry; background TTL merges reclaim expired data.
            </p>
          </div>
        </div>
        {retention.error && <ErrorNotice>{retention.error}</ErrorNotice>}
        {policy && (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError("");
              setNotice("");
              try {
                await api("/api/retention", json("PUT", policy));
                await retention.load();
                setNotice(
                  "Retention policy saved. The new policy applies to future arrivals.",
                );
              } catch (err) {
                setError((err as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            <fieldset disabled={user.role !== "ADMINISTRATOR" || busy}>
              <div className="global-retention">
                <label>
                  Global retention
                  <input
                    aria-label="Global retention days"
                    type="number"
                    min="1"
                    max="3650"
                    required
                    value={policy.global_days}
                    onChange={(e) =>
                      setPolicy({
                        ...policy,
                        global_days: Number(e.target.value),
                      })
                    }
                  />
                </label>
                <span>days</span>
                <div className="presets">
                  {[30, 60, 90, 180, 365].map((days) => (
                    <button
                      type="button"
                      key={days}
                      className={policy.global_days === days ? "selected" : ""}
                      onClick={() =>
                        setPolicy({ ...policy, global_days: days })
                      }
                    >
                      {days}d
                    </button>
                  ))}
                </div>
              </div>
              <div className="retention-grid">
                {families
                  .filter(([id]) => id !== "unified")
                  .map(([id, label]) => (
                    <label key={id}>
                      <span>{label}</span>
                      <div>
                        <input
                          type="number"
                          min="1"
                          max="3650"
                          aria-label={`${label} retention days`}
                          placeholder={String(policy.global_days)}
                          value={policy.per_type[id] ?? ""}
                          onChange={(e) => {
                            const per_type = { ...policy.per_type };
                            if (e.target.value === "") delete per_type[id];
                            else per_type[id] = Number(e.target.value);
                            setPolicy({ ...policy, per_type });
                          }}
                        />
                        <span>days</span>
                      </div>
                    </label>
                  ))}
              </div>
            </fieldset>
            <p className="muted">
              Leave a category blank to use the global policy.
            </p>
            {error && <ErrorNotice>{error}</ErrorNotice>}
            {notice && (
              <div role="status" className="notice success">
                {notice}
              </div>
            )}
            {user.role === "ADMINISTRATOR" && (
              <button className="primary" disabled={busy}>
                {busy ? "Saving…" : "Save retention policy"}
              </button>
            )}
          </form>
        )}
      </section>
    </>
  );
}
function Diagnostics({
  user,
  navigate,
}: {
  user: User;
  navigate: (path: string) => void;
}) {
  const { data, error, busy, load } = useData<Stats>("/api/stats");
  const [notice, setNotice] = useState("");
  const metrics = data
    ? [
        ["Messages received", formatNumber(data.messages_received)],
        ["Messages parsed", formatNumber(data.messages_parsed)],
        ["Parse failures", formatNumber(data.parse_failures)],
        ["Events inserted", formatNumber(data.events_inserted)],
        ["Queue depth", formatNumber(data.queue_depth)],
        ["Spool usage", bytes(data.spool_bytes)],
        ["Messages dropped", formatNumber(data.messages_dropped)],
        ["Events / sec", formatNumber(data.events_per_second)],
        ["Bytes / sec", bytes(data.bytes_per_second)],
        ["Last received", timestamp(data.last_event_received)],
      ]
    : [];
  return (
    <>
      <div className="section-toolbar">
        <div>
          <h2>
            <Terminal size={18} /> Syslog receiver
          </h2>
          <p>
            Observed listener and ingestion counters from the running collector.
          </p>
        </div>
        <button disabled={busy} onClick={() => void load()}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>
      <SyslogTLSCertificate user={user} />
      {error && <ErrorNotice>{error}</ErrorNotice>}
      {!data ? (
        busy ? (
          <Loading />
        ) : null
      ) : (
        <>
          <div className="metric-grid">
            {metrics.map(([label, value]) => (
              <div key={label}>
                <span>{label}</span>
                <strong
                  className={
                    label === "Messages dropped" && data.messages_dropped
                      ? "text-danger"
                      : ""
                  }
                >
                  {value}
                </strong>
              </div>
            ))}
          </div>
          <section className="panel">
            <h3>Listeners</h3>
            {data.listeners?.length ? (
              <ObservedValues value={data.listeners} />
            ) : (
              <p className="muted">
                No active listener details reported by the collector.
              </p>
            )}
          </section>
          <div className="diagnostics-actions">
            <div>
              <h3>Parsing diagnostics</h3>
              <p>
                Inspect retained malformed events, sender information and
                original payloads.
              </p>
            </div>
            <button onClick={() => navigate("/logs/parsing")}>
              View parsing failures
              <ArrowRight size={14} />
            </button>
          </div>
          <div className="diagnostics-actions">
            <div>
              <h3>Reverse DNS cache</h3>
              <p>
                Resolution runs independently of ingestion and search. Clearing
                the cache triggers new lookups when requested.
              </p>
            </div>
            <button
              disabled={user.role !== "ADMINISTRATOR"}
              onClick={async () => {
                try {
                  await api("/api/dns/cache", { method: "DELETE" });
                  setNotice("DNS cache cleared.");
                } catch (e) {
                  setNotice((e as Error).message);
                }
              }}
            >
              Clear DNS cache
            </button>
          </div>
          {notice && (
            <div role="status" className="notice">
              {notice}
            </div>
          )}
          <section className="panel">
            <h3>Receiving no events?</h3>
            <ol className="troubleshooting-list">
              <li>
                Verify the firewall has committed its syslog server profile.
              </li>
              <li>
                Attach a log forwarding profile to the applicable security rules
                and enable Log at Session End.
              </li>
              <li>
                Check the PAN-OS service route, destination port, routing and
                transport selection.
              </li>
              <li>
                For TLS, verify certificate trust, hostname validation and the
                listener’s configured port.
              </li>
            </ol>
            <button onClick={() => navigate("/administration/setup")}>
              Open firewall setup
            </button>
          </section>
        </>
      )}
    </>
  );
}
function ObservedPage({
  path,
  title,
  description,
  icon,
}: {
  path: string;
  title: string;
  description: string;
  icon: string;
}) {
  const { data, error, busy, load, refreshFailed } =
    useData<Record<string, unknown>>(path);
  return (
    <>
      <div className="section-toolbar">
        <div>
          <h2>
            {icon === "security" ? (
              <ShieldCheck size={18} />
            ) : (
              <Database size={18} />
            )}{" "}
            {title}
          </h2>
          <p>{description}</p>
        </div>
        <button disabled={busy} onClick={() => void load()}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>
      {error && <ErrorNotice>{error}</ErrorNotice>}
      {!data ? (
        busy ? (
          <Loading />
        ) : null
      ) : (
        <FreshHostObservation value={data} refreshFailed={refreshFailed}>
          <ObservedValues value={data} />
        </FreshHostObservation>
      )}
    </>
  );
}
function ObservedValues({ value }: { value: unknown }) {
  if (value === null || value === undefined)
    return <span className="muted">Not reported</span>;
  if (Array.isArray(value))
    return value.length ? (
      <div className="observed-list">
        {value.map((v, i) => (
          <div key={i}>
            <ObservedValues value={v} />
          </div>
        ))}
      </div>
    ) : (
      <span className="muted">None reported</span>
    );
  if (typeof value === "object")
    return (
      <dl className="observed-values">
        {Object.entries(value as Record<string, unknown>).map(([key, v]) => (
          <div key={key}>
            <dt>{key.replaceAll("_", " ")}</dt>
            <dd>
              <ObservedValues value={v} />
            </dd>
          </div>
        ))}
      </dl>
    );
  if (typeof value === "boolean") return <span>{value ? "Yes" : "No"}</span>;
  if (
    typeof value === "string" &&
    /^(enabled|disabled|unknown|unverified|not_validated|configured|unavailable|healthy|degraded|pending|strict|development|production|manual|automatic)$/i.test(
      value,
    )
  )
    return <Status value={value} />;
  return <span>{String(value)}</span>;
}
function Setup() {
  return (
    <>
      <div className="section-toolbar">
        <div>
          <h2>Forward PAN-OS logs to Captain’s Log</h2>
          <p>
            Standard syslog output is supported. A custom message format is not
            required.
          </p>
        </div>
      </div>
      <div className="setup-flow">
        {[
          [
            "Create a syslog server profile",
            "Device → Server Profiles → Syslog",
            "Create a syslog server profile and add this appliance’s reachable IP address or DNS name. Choose UDP, TCP or TLS and match the configured collector port. Typical ports: UDP/TCP 514 and TLS 6514.",
          ],
          [
            "Create a log forwarding profile",
            "Objects → Log Forwarding",
            "Create a log forwarding profile. Add match lists for the log categories you want to retain and select the syslog server profile.",
          ],
          [
            "Attach forwarding to security rules",
            "Policies → Security → Actions",
            "For each applicable rule, select the configured log forwarding profile and enable Log at Session End. Creating the server profile alone does not forward Traffic logs.",
          ],
          [
            "Configure management-plane forwarding",
            "Device → Log Settings",
            "Configure the supported System, Configuration, User-ID, HIP Match, GlobalProtect and other management log settings relevant to your PAN-OS release.",
          ],
          [
            "Commit and verify",
            "Commit → Administration / Firewalls → Logs / Traffic",
            "Commit the firewall changes. Generate matching traffic, verify the receiver counters increase and confirm the firewall appears in inventory. Open Traffic to inspect the received event.",
          ],
        ].map(([title, path, body], i) => (
          <article key={title}>
            <span className="step-number">{i + 1}</span>
            <div>
              <h3>{title}</h3>
              <code>{path}</code>
              <p>{body}</p>
            </div>
          </article>
        ))}
      </div>
      <section className="panel" aria-labelledby="empty-log-guide">
        <div className="section-toolbar">
          <div>
            <h2 id="empty-log-guide">Understanding empty log views</h2>
            <p>
              Views start with the last hour. Check the time range and filter,
              then compare with Monitor logs on the firewall. Forwarding starts
              collecting new events; it does not import the firewall’s history.
            </p>
          </div>
        </div>
        <div className="setup-flow">
          <article>
            <div>
              <h3>Refresh at your own pace</h3>
              <p>
                Use the Refresh selector above the table to choose 5, 10, 30 or
                60 seconds, or Manual. Pause keeps the current results in place;
                Resume immediately loads the latest events. The refresh button
                works while paused. These settings stay with your account in
                this browser. Refresh also waits while you browse older rows.
              </p>
            </div>
          </article>
          {families
            .filter(([kind]) => kind !== "tunnel")
            .map(([kind, label]) => (
              <article key={kind}>
                <div>
                  <h3>{label}</h3>
                  <p>{categoryGuidance[kind]}</p>
                </div>
              </article>
            ))}
          <article>
            <div>
              <h3>Tunnel Inspection · not available yet</h3>
              <p>
                Native Tunnel parsing is not supported in this development
                build. Forwarded messages are retained in Parsing diagnostics. A
                wider time range will not enable this parser.
              </p>
            </div>
          </article>
        </div>
      </section>
      <div className="notice">
        Captain’s Log is an independent open-source project and is not affiliated
        with, endorsed by, or sponsored by Palo Alto Networks. Palo Alto
        Networks, PAN-OS, and related names are trademarks of their respective
        owner.
      </div>
    </>
  );
}
