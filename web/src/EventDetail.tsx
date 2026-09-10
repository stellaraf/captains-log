import { useEffect, useState } from "react";
import { ArrowLeft, Copy, FileText, Server } from "lucide-react";
import { api } from "./api";
import type { EventRecord } from "./types";
import { columns } from "./types";
import { timestamp } from "./utils";
function valueText(event: EventRecord, key: string) {
  const value = event[key];
  return key.endsWith("_at")
    ? timestamp(value)
    : value == null || value === ""
      ? "—"
      : typeof value === "object"
        ? JSON.stringify(value, null, 2)
        : String(value);
}
import { ErrorNotice, Loading, Status } from "./components";
export function safeReturnTo(value: string | null, fallback: string): string {
  if (
    !value ||
    !/^\/(logs|administration)\//.test(value) ||
    value.startsWith("//")
  )
    return fallback;
  const parsed = new URL(value, location.origin);
  return parsed.origin === location.origin
    ? parsed.pathname + parsed.search
    : fallback;
}
export function EventDetail({
  id,
  navigate,
}: {
  id: string;
  navigate: (path: string) => void;
}) {
  const params = new URLSearchParams(location.search);
  const type = params.get("type") || "";
  const at = params.get("at") || "";
  const returnTo = safeReturnTo(
    params.get("returnTo"),
    `/logs/${type || "traffic"}`,
  );
  const [event, setEvent] = useState<EventRecord>();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [section, setSection] = useState(params.get("section") || "overview");
  useEffect(() => {
    let current = true;
    api<{ event: EventRecord }>(
      `/api/events/${encodeURIComponent(id)}?${new URLSearchParams({ at, type })}`,
    )
      .then((r) => {
        if (current) setEvent(r.event);
      })
      .catch((e) => {
        if (current) setError(e.message);
      });
    return () => {
      current = false;
    };
  }, [id, at, type]);
  function tab(next: string) {
    setSection(next);
    const p = new URLSearchParams(location.search);
    p.set("section", next);
    history.replaceState({}, "", `${location.pathname}?${p}`);
  }
  return (
    <div className="admin-workspace resource-page">
      <a
        className="back-link"
        href={returnTo}
        onClick={(e) => {
          if (!e.metaKey && !e.ctrlKey) {
            e.preventDefault();
            navigate(returnTo);
          }
        }}
      >
        <ArrowLeft size={15} /> Back to log results
      </a>
      {error && (
        <ErrorNotice>
          {error} The record may have expired under retention. Return to the
          results and search again.
        </ErrorNotice>
      )}
      {!event && !error ? (
        <Loading label="Loading event…" />
      ) : (
        event && (
          <>
            <div className="resource-heading">
              <span className="resource-icon">
                <FileText size={24} />
              </span>
              <div>
                <h2>{String(event.log_type)} event</h2>
                <p className="mono">{id}</p>
              </div>
              <Status value={event.parse_status} />
            </div>
            <div className="resource-subtitle">
              <span>{timestamp(event.received_at)}</span>
              <span>
                <Server size={13} />
                {String(
                  event.device_name || event.serial || "Unknown firewall",
                )}
              </span>
              <span>Original event preserved</span>
            </div>
            <nav className="section-tabs" aria-label="Event sections">
              {[
                ["overview", "Overview"],
                ["fields", "All fields"],
                ["raw", "Original payload"],
              ].map(([key, label]) => (
                <a
                  key={key}
                  href={`${location.pathname}?${new URLSearchParams({ ...Object.fromEntries(params), section: key })}`}
                  aria-current={section === key ? "page" : undefined}
                  onClick={(e) => {
                    e.preventDefault();
                    tab(key);
                  }}
                >
                  {label}
                </a>
              ))}
            </nav>
            {section === "overview" ? (
              <>
                <section className="resource-section">
                  <h3>Connection</h3>
                  <dl className="event-details">
                    {[
                      "src_ip",
                      "dst_ip",
                      "src_port",
                      "dst_port",
                      "src_zone",
                      "dst_zone",
                      "src_user",
                      "app",
                      "action",
                      "rule",
                      "session_end_reason",
                      "bytes",
                    ].map((key) => (
                      <div key={key}>
                        <dt>{columns[key]}</dt>
                        <dd>{valueText(event, key)}</dd>
                      </div>
                    ))}
                  </dl>
                </section>
                <section className="resource-section">
                  <h3>Provenance</h3>
                  <dl className="event-details">
                    {[
                      "received_at",
                      "generated_at",
                      "ingested_at",
                      "sender_ip",
                      "device_name",
                      "serial",
                      "vsys",
                      "schema_id",
                      "panos_version",
                      "parser_version",
                      "parse_status",
                      "parse_error",
                    ].map((key) => (
                      <div key={key}>
                        <dt>{columns[key]}</dt>
                        <dd>{valueText(event, key)}</dd>
                      </div>
                    ))}
                  </dl>
                </section>
              </>
            ) : section === "fields" ? (
              <section className="resource-section">
                <h3>Parsed fields</h3>
                <p className="muted">
                  Normalized fields, original schema fields and extensions
                  retained from this event.
                </p>
                <dl className="event-details">
                  {Object.entries(event)
                    .filter(([key]) => !["raw", "raw_base64"].includes(key))
                    .map(([key, value]) => (
                      <div key={key}>
                        <dt>{columns[key] || key}</dt>
                        <dd>
                          {value && typeof value === "object"
                            ? JSON.stringify(value, null, 2)
                            : valueText(event, key)}
                        </dd>
                      </div>
                    ))}
                </dl>
              </section>
            ) : (
              <section className="resource-section">
                <div className="section-toolbar">
                  <div>
                    <h3>Original syslog payload</h3>
                    <p>
                      The exact received message is retained independently of
                      parsing.
                    </p>
                  </div>
                  <button
                    onClick={() =>
                      void navigator.clipboard
                        .writeText(event.raw)
                        .then(() => setNotice("Raw message copied."))
                        .catch(() =>
                          setNotice(
                            "Clipboard is unavailable. Select and copy the raw message.",
                          ),
                        )
                    }
                  >
                    <Copy size={14} /> Copy raw message
                  </button>
                </div>
                <pre className="raw-message full-raw">{event.raw}</pre>
                <details>
                  <summary>Original bytes (Base64)</summary>
                  <pre className="raw-message">
                    {String(event.raw_base64 || "Unavailable")}
                  </pre>
                </details>
              </section>
            )}
            {notice && (
              <div className="notice" role="status">
                {notice}
              </div>
            )}
          </>
        )
      )}
    </div>
  );
}
