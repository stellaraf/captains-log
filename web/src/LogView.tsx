import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  Check,
  ChevronRight,
  Columns3,
  Download,
  Filter,
  FolderOpen,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Save,
  Search,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { api, download, json, saveBlob } from "./api";
import { columns, defaultLayout, families } from "./types";
import type {
  DNSResult,
  EventRecord,
  ExportJob,
  Field,
  Layout,
  SavedFilter,
  Stats,
  User,
} from "./types";
import {
  buildClause,
  bytes,
  combine,
  formatNumber,
  rangeBounds,
  timestamp,
  visibleCSV,
} from "./utils";
import { Empty, ErrorNotice, Loading, Modal, Status } from "./components";
import { EmptyLogCategory, LogCategoryScope } from "./LogCategoryHelp";
import { usePreferences } from "./preferences";
import {
  readRefreshPreferences,
  refreshIntervals,
  writeRefreshPreferences,
} from "./refresh";
import {
  ColumnEditor,
  FilterBuilder,
  SaveFilter,
  SavedFilters,
} from "./Filters";

const timeRanges = [
  ["15m", "Last 15 minutes"],
  ["1h", "Last hour"],
  ["6h", "Last 6 hours"],
  ["24h", "Last 24 hours"],
  ["7d", "Last 7 days"],
  ["30d", "Last 30 days"],
] as const;
interface SearchResult {
  events: EventRecord[];
  next_cursor: string;
  elapsed_ms: number;
}
interface SearchSnapshot {
  query: string;
  range: string;
  bounds: { from: string; to: string };
  sort: string;
  order: string;
}
interface SearchContext {
  result?: SearchResult;
  snapshot?: SearchSnapshot;
  layout: Layout;
  scrollTop: number;
  resolve: boolean;
  paused: boolean;
  intervalSeconds: number;
  lastRefresh: string;
}
// Keep at most three return contexts in memory; log payloads are never written to browser storage.
const searchContexts = new Map<string, SearchContext>();
export function LogView({
  type,
  user,
  stats,
  savedOpen,
  closeSaved,
  navigate,
}: {
  type: string;
  user: User;
  stats?: Stats;
  savedOpen: boolean;
  closeSaved: () => void;
  navigate: (path: string) => void;
}) {
  const { density } = usePreferences();
  const [coarsePointer, setCoarsePointer] = useState(
    matchMedia("(pointer: coarse)").matches,
  );
  useEffect(() => {
    const media = matchMedia("(pointer: coarse)");
    const update = () => setCoarsePointer(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  const ROW_HEIGHT = coarsePointer || density === "comfortable" ? 44 : 32;
  const HEADER_HEIGHT = coarsePointer ? 48 : 36;
  const restored = useRef(
    searchContexts.get(
      new URLSearchParams(location.search).get("context") || "",
    ),
  );
  const restorePending = useRef(!!restored.current);
  const contextId = useRef(
    new URLSearchParams(location.search).get("context") || crypto.randomUUID(),
  );
  const initialSearch = new URLSearchParams(location.search).get("query") || "";
  const [draft, setDraft] = useState(initialSearch);
  const [query, setQuery] = useState(initialSearch);
  const [range, setRange] = useState(
    new URLSearchParams(location.search).get("range") || "1h",
  );
  const [layout, setLayout] = useState<Layout>(
    restored.current?.layout || defaultLayout(type),
  );
  const [layoutReady, setLayoutReady] = useState(false);
  const [fields, setFields] = useState<Field[]>([]);
  const [result, setResult] = useState<SearchResult | undefined>(
    restored.current?.result,
  );
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [resolve, setResolve] = useState(restored.current?.resolve || false);
  const [dns, setDNS] = useState<Record<string, DNSResult>>({});
  const [intervalSeconds, setIntervalSeconds] = useState(
    restored.current?.intervalSeconds ?? readRefreshPreferences(user.id).intervalSeconds,
  );
  const [paused, setPaused] = useState(
    restored.current?.paused ?? readRefreshPreferences(user.id).paused,
  );
  const pausedRef = useRef(paused);
  const intervalRef = useRef(intervalSeconds);
  const activeSearch = useRef<{
    id: number;
    automatic: boolean;
    controller: AbortController;
  } | undefined>(undefined);
  useEffect(() => {
    writeRefreshPreferences(user.id, { intervalSeconds, paused });
  }, [user.id, intervalSeconds, paused]);
  const [scrollTop, setScrollTop] = useState(restored.current?.scrollTop || 0);
  const [viewHeight, setViewHeight] = useState(600);
  const [modal, setModal] = useState<
    "builder" | "columns" | "save" | "load" | "export" | null
  >(null);
  const [context, setContext] = useState<{ column: string; value: unknown }>();
  const [connector, setConnector] = useState("and");
  const [job, setJob] = useState<ExportJob>();
  const [lastRefresh, setLastRefresh] = useState(
    restored.current?.lastRefresh || "",
  );
  const [notice, setNotice] = useState("");
  const scroller = useRef<HTMLDivElement>(null);
  const request = useRef(0);
  const snapshot = useRef<SearchSnapshot | undefined>(
    restored.current?.snapshot,
  );
  const fetching = useRef(false);
  const [customFrom, setCustomFrom] = useState(
    new URLSearchParams(location.search).get("from") || "",
  );
  const [customTo, setCustomTo] = useState(
    new URLSearchParams(location.search).get("to") || "",
  );
  function eventURL(event: EventRecord) {
    const p = new URLSearchParams({
      query,
      range,
      sort: layout.sort,
      order: layout.order,
      columns: layout.columns.join(","),
      context: contextId.current,
    });
    if (customFrom) p.set("from", customFrom);
    if (customTo) p.set("to", customTo);
    const received = /(?:Z|[+-]\d{2}:?\d{2})$/.test(event.received_at)
      ? event.received_at
      : event.received_at.replace(" ", "T") + "Z";
    const detail = new URLSearchParams({
      at: new Date(received).toISOString(),
      type: event.log_type,
      returnTo: `/logs/${type}?${p}`,
    });
    return `/logs/${type}/events/${encodeURIComponent(event.id)}?${detail}`;
  }
  function rememberResults(event: EventRecord) {
    searchContexts.set(contextId.current, {
      result,
      snapshot: snapshot.current,
      layout,
      scrollTop: scroller.current?.scrollTop || 0,
      resolve,
      paused,
      intervalSeconds,
      lastRefresh,
    });
    while (searchContexts.size > 3)
      searchContexts.delete(searchContexts.keys().next().value!);
    const returnTo = new URL(eventURL(event), location.origin).searchParams.get(
      "returnTo",
    );
    if (returnTo) history.replaceState({}, "", returnTo);
  }
  const canWrite = user.role !== "VIEWER";
  useEffect(() => {
    let current = true;
    api<{ fields: Field[] }>("/api/fields")
      .then((r) => {
        if (current) setFields(r.fields);
      })
      .catch((e) => {
        if (current) setError(e.message);
      });
    api<Layout>(`/api/layouts/${type}`)
      .then((r) => {
        if (current) {
          if (restored.current) return;
          const base = r.columns?.length ? r : defaultLayout(type);
          const params = new URLSearchParams(location.search);
          const chosen = params
            .get("columns")
            ?.split(",")
            .filter((c) => columns[c]);
          setLayout({
            ...base,
            columns: chosen?.length
              ? chosen
              : base.columns.filter((c) => columns[c]),
            sort: params.get("sort") || base.sort,
            order:
              params.get("order") === "asc"
                ? "asc"
                : params.get("order") === "desc"
                  ? "desc"
                  : base.order,
          });
        }
      })
      .catch((e) => {
        if (current && e.status !== 404) setError(e.message);
      })
      .finally(() => {
        if (current) setLayoutReady(true);
      });
    return () => {
      current = false;
      request.current++;
      activeSearch.current?.controller.abort();
    };
  }, [type]);
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const observer = new ResizeObserver(() => setViewHeight(el.clientHeight));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  const search = useCallback(
    async (more = false, auto = false) => {
      if (!layoutReady || (fetching.current && auto)) return;
      if (auto && (pausedRef.current || !intervalRef.current || (scroller.current?.scrollTop || 0) > 0)) return;
      activeSearch.current?.controller.abort();
      fetching.current = true;
      const id = ++request.current;
      const controller = new AbortController();
      activeSearch.current = { id, automatic: auto, controller };
      setBusy(true);
      setError("");
      try {
        let bounds;
        if (more && snapshot.current) bounds = snapshot.current.bounds;
        else if (range === "custom") {
          if (
            !customFrom ||
            !customTo ||
            new Date(customFrom) >= new Date(customTo)
          )
            throw new Error("Choose a valid start and end time.");
          bounds = {
            from: new Date(customFrom).toISOString(),
            to: new Date(customTo).toISOString(),
          };
        } else bounds = rangeBounds(range);
        const snap = {
          query,
          range,
          bounds,
          sort: layout.sort,
          order: layout.order,
        };
        const p = new URLSearchParams({
          type,
          query,
          from: bounds.from,
          to: bounds.to,
          limit: "200",
          sort: layout.sort,
          order: layout.order,
        });
        if (more && result?.next_cursor) p.set("cursor", result.next_cursor);
        const data = await api<SearchResult>(`/api/logs?${p}`, { signal: controller.signal });
        if (id !== request.current) return;
        snapshot.current = snap;
        setResult((previous) =>
          more && previous
            ? { ...data, events: [...previous.events, ...data.events] }
            : data,
        );
        setLastRefresh(new Date().toISOString());
        if (!more && !auto && scroller.current) scroller.current.scrollTop = 0;
      } catch (e) {
        if (id === request.current) setError((e as Error).message);
      } finally {
        if (id === request.current) {
          fetching.current = false;
          activeSearch.current = undefined;
          setBusy(false);
        }
      }
    },
    [
      layoutReady,
      query,
      range,
      type,
      layout.sort,
      layout.order,
      result?.next_cursor,
      customFrom,
      customTo,
    ],
  );
  const searchRef = useRef(search);
  searchRef.current = search;
  function stopAutomaticRequest() {
    const active = activeSearch.current;
    if (!active?.automatic) return;
    request.current++;
    active.controller.abort();
    activeSearch.current = undefined;
    fetching.current = false;
    setBusy(false);
  }
  function togglePause() {
    const next = !(pausedRef.current || intervalSeconds === 0);
    pausedRef.current = next;
    setPaused(next);
    if (next) stopAutomaticRequest();
    else {
      if (!intervalSeconds) {
        intervalRef.current = 10;
        setIntervalSeconds(10);
      }
      void searchRef.current();
    }
  }
  function changeInterval(seconds: number) {
    intervalRef.current = seconds;
    setIntervalSeconds(seconds);
    if (!seconds) stopAutomaticRequest();
  }
  useEffect(() => {
    if (!layoutReady) return;
    if (restorePending.current) {
      restorePending.current = false;
      if (scroller.current)
        scroller.current.scrollTop = restored.current?.scrollTop || 0;
      return;
    }
    void searchRef.current();
  }, [query, range, type, layout.sort, layout.order, layoutReady]);
  useEffect(() => {
    if (!intervalSeconds || paused) return;
    const id = setInterval(
      () => void searchRef.current(false, true),
      intervalSeconds * 1000,
    );
    return () => clearInterval(id);
  }, [intervalSeconds, paused]);
  useEffect(() => {
    if (!resolve || !result?.events.length) return;
    let disposed = false;
    const first = Math.max(
      0,
      Math.floor((scrollTop - HEADER_HEIGHT) / ROW_HEIGHT) - 8,
    );
    const ips = [
      ...new Set(
        result.events
          .slice(first, first + Math.ceil(viewHeight / ROW_HEIGHT) + 16)
          .flatMap((e) => [e.src_ip, e.dst_ip])
          .filter(Boolean),
      ),
    ].slice(0, 200);
    const run = () =>
      api<{ results: Record<string, DNSResult> }>(
        "/api/dns/resolve",
        json("POST", { ips }),
      )
        .then((r) => {
          if (!disposed) setDNS((old) => ({ ...old, ...r.results }));
        })
        .catch(() => {
          if (!disposed)
            setNotice(
              "Hostname resolution is temporarily unavailable; original IP addresses remain available.",
            );
        });
    const initial = setTimeout(run, 150);
    const timer = setInterval(run, 3000);
    return () => {
      disposed = true;
      clearTimeout(initial);
      clearInterval(timer);
    };
  }, [resolve, result, scrollTop, viewHeight, ROW_HEIGHT, HEADER_HEIGHT]);
  useEffect(() => {
    if (
      !job ||
      ["completed", "complete", "failed", "error"].includes(job.status)
    )
      return;
    const timer = setInterval(
      () =>
        api<ExportJob>(`/api/exports/${encodeURIComponent(job.id)}`)
          .then(setJob)
          .catch((e) => setError(e.message)),
      1500,
    );
    return () => clearInterval(timer);
  }, [job]);
  const visibleColumns = layout.columns.filter(
    (c) => resolve || !c.endsWith("_hostname"),
  );
  const widths = visibleColumns.map(
    (c) => layout.widths[c] || (/hostname|user/.test(c) ? 160 : 125),
  );
  const detailWidth = coarsePointer ? 62 : 44;
  const totalWidth = widths.reduce((a, b) => a + b, detailWidth);
  const rowHeight = ROW_HEIGHT;
  const start = Math.max(
    0,
    Math.floor((scrollTop - HEADER_HEIGHT) / rowHeight) - 8,
  );
  const end = Math.min(
    result?.events.length || 0,
    start + Math.ceil(viewHeight / rowHeight) + 16,
  );
  const rows = result?.events.slice(start, end) || [];
  const enriched = useMemo(
    () =>
      result?.events.map((e) => ({
        ...e,
        src_hostname: resolve ? dns[e.src_ip]?.hostname || "" : "",
        dst_hostname: resolve ? dns[e.dst_ip]?.hostname || "" : "",
      })) || [],
    [result, resolve, dns],
  );
  async function saveLayout(value: Layout) {
    await api(`/api/layouts/${type}`, json("PUT", value));
    setLayout(value);
  }
  function resize(column: string, clientX: number, width: number) {
    const move = (e: PointerEvent) =>
      setLayout((old) => ({
        ...old,
        widths: {
          ...old.widths,
          [column]: Math.min(800, Math.max(80, width + e.clientX - clientX)),
        },
      }));
    const up = (e: PointerEvent) => {
      document.removeEventListener("pointermove", move);
      document.removeEventListener("pointerup", up);
      const next = {
        ...layout,
        widths: {
          ...layout.widths,
          [column]: Math.min(800, Math.max(80, width + e.clientX - clientX)),
        },
      };
      void saveLayout(next).catch((e) => setError(e.message));
    };
    document.addEventListener("pointermove", move);
    document.addEventListener("pointerup", up);
  }
  async function apply(next = draft) {
    setError("");
    try {
      await api("/api/query/validate", json("POST", { query: next }));
      setDraft(next);
      if (query === next) void searchRef.current();
      else setQuery(next);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  function loadFilter(item: SavedFilter) {
    if (item.log_type !== type) {
      const params = new URLSearchParams({
        query: item.query,
        range: item.time_range || "1h",
        columns: item.columns.join(","),
        sort: item.sort || "received_at",
        order: item.order || "desc",
      });
      navigate(`/logs/${item.log_type}?${params}`);
      return;
    }
    setDraft(item.query);
    setQuery(item.query);
    setRange(
      timeRanges.some((r) => r[0] === item.time_range) ? item.time_range : "1h",
    );
    if (item.columns?.length) {
      const next = {
        ...layout,
        columns: item.columns.filter((c) => columns[c]),
        sort: item.sort || "received_at",
        order: item.order || "desc",
      };
      void saveLayout(next).catch((e) => setError(e.message));
    }
  }
  const filter: SavedFilter = {
    name: "",
    description: "",
    query,
    log_type: type,
    columns: layout.columns,
    time_range: range,
    sort: layout.sort,
    order: layout.order,
    favorite: false,
  };
  function valueText(event: EventRecord, column: string): string {
    if (column === "src_hostname" || column === "dst_hostname") {
      const ip = String(
        event[column === "src_hostname" ? "src_ip" : "dst_ip"] || "",
      );
      const r = dns[ip];
      return r?.hostname || (r?.status === "pending" ? "Resolving…" : "—");
    }
    if (column.endsWith("_at")) return timestamp(event[column]);
    if (column.startsWith("bytes")) return bytes(event[column]);
    return event[column] === null ||
      event[column] === undefined ||
      event[column] === ""
      ? "—"
      : String(event[column]);
  }
  const field = fields.find((f) => f.column === context?.column);
  const title = families.find((f) => f[0] === type)?.[1] || "Parsing";
  return (
    <div className="log-workspace">
      <div className="query-panel">
        <form
          className="query-bar"
          onSubmit={(e) => {
            e.preventDefault();
            void apply();
          }}
        >
          <div className="query-input">
            <Search size={17} />
            <input
              aria-label="Filter query"
              spellCheck={false}
              placeholder="Enter a PAN-OS filter, e.g. ( addr.src in 10.0.0.0/8 ) and ( action eq allow )"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
            {draft && (
              <button
                type="button"
                className="icon-button"
                aria-label="Clear filter"
                onClick={() => {
                  setDraft("");
                  void apply("");
                }}
              >
                <X size={14} />
              </button>
            )}
          </div>
          <button className="primary" disabled={busy}>
            <Check size={14} />
            Apply
          </button>
          <button type="button" onClick={() => setModal("builder")}>
            <Plus size={14} />
            Add filter
          </button>
          <button
            type="button"
            title="Save filter"
            disabled={!canWrite}
            onClick={() => setModal("save")}
          >
            <Save size={14} />
            Save
          </button>
          <button
            type="button"
            title="Load filter"
            onClick={() => setModal("load")}
          >
            <FolderOpen size={14} />
            Load
          </button>
        </form>
        <div className="query-help">
          <span>
            <Filter size={12} /> PAN-OS query syntax
          </span>
          <code>and</code>
          <code>or</code>
          <code>not</code>
          <code>eq</code>
          <code>in</code>
          <code>contains</code>
          <span className="query-validation">
            {query ? "Filter applied" : "All events in time range"}
          </span>
        </div>
      </div>
      <div className="table-toolbar">
        <div className="toolbar-group">
          <button
            className="icon-button"
            title="Refresh logs"
            aria-label="Refresh logs"
            disabled={busy}
            onClick={() => void search()}
          >
            <RefreshCw className={busy ? "spin" : ""} size={15} />
          </button>
          <span className="toolbar-divider" />
          <button
            onClick={togglePause}
            title={paused || !intervalSeconds ? "Resume automatic refresh and refresh now" : "Pause automatic refresh; keep current results"}
            aria-pressed={paused || intervalSeconds === 0}
          >
            {paused || !intervalSeconds ? <Play size={13} /> : <Pause size={13} />}{" "}
            {paused || !intervalSeconds ? "Resume" : "Pause"}
          </button>
          <label className="inline-label">
            Refresh
            <select
              aria-label="Auto-refresh interval"
              value={intervalSeconds}
              onChange={(e) => changeInterval(Number(e.target.value))}
            >
              {refreshIntervals.map((n) => (
                <option key={n} value={n}>
                  {n === 0 ? "Manual" : n === 60 ? "Every minute" : `Every ${n} seconds`}
                </option>
              ))}
            </select>
          </label>
          <span className="toolbar-divider" />
          <label className="inline-label">
            Time range
            <select
              aria-label="Time range"
              value={range}
              onChange={(e) => setRange(e.target.value)}
            >
              {timeRanges.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
              <option value="custom">Custom range</option>
            </select>
          </label>
        </div>
        <div className="toolbar-group">
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={resolve}
              onChange={(e) => setResolve(e.target.checked)}
            />
            Resolve hostnames
          </label>
          <button onClick={() => setModal("columns")}>
            <Columns3 size={14} />
            Columns
          </button>
          <button
            disabled={!canWrite || !result}
            onClick={() => setModal("export")}
          >
            <Download size={14} />
            Export CSV
          </button>
        </div>
      </div>
      {range === "custom" && (
        <div className="custom-range">
          <label>
            From
            <input
              type="datetime-local"
              value={customFrom}
              onChange={(e) => setCustomFrom(e.target.value)}
            />
          </label>
          <label>
            To
            <input
              type="datetime-local"
              value={customTo}
              onChange={(e) => setCustomTo(e.target.value)}
            />
          </label>
          <button onClick={() => void search()}>Apply range</button>
          <span className="muted">
            Times use your browser’s local time zone.
          </span>
        </div>
      )}
      {error && <ErrorNotice>{error}</ErrorNotice>}
      {notice && (
        <div className="notice">
          <span>{notice}</span>
          <button
            className="icon-button"
            aria-label="Dismiss notice"
            onClick={() => setNotice("")}
          >
            <X size={14} />
          </button>
        </div>
      )}
      <LogCategoryScope type={type} />
      {type === "parsing" && (
        <div className="notice warning">
          Malformed and unrecognized messages are retained. Open a row to
          inspect the original event and parser diagnostics.
        </div>
      )}
      {scrollTop > 0 && !paused && intervalSeconds > 0 && (
        <div className="scroll-notice">
          Auto-refresh waits while you inspect older rows.{" "}
          <button
            onClick={() => {
              scroller.current?.scrollTo({ top: 0 });
              void search();
            }}
          >
            Return to latest
          </button>
        </div>
      )}
      <div
        ref={scroller}
        className="table-scroll"
        role="region"
        aria-label={`${title} log results`}
        tabIndex={0}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        <table
          className="log-table"
          style={{ width: totalWidth }}
          aria-label={`${title} logs`}
          aria-rowcount={result?.events.length ? result.events.length + 1 : 1}
        >
          <colgroup>
            <col style={{ width: detailWidth }} />
            {visibleColumns.map((c, i) => (
              <col key={c} style={{ width: widths[i] }} />
            ))}
          </colgroup>
          <thead>
            <tr>
              <th aria-label="Details" />
              <>
                {visibleColumns.map((column, i) => (
                  <th
                    key={column}
                    aria-sort={
                      layout.sort === column
                        ? layout.order === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                    }
                  >
                    <button
                      className="sort-button"
                      disabled={
                        column.endsWith("_hostname") ||
                        ["raw", "generated_at"].includes(column)
                      }
                      onClick={() => {
                        const next = {
                          ...layout,
                          sort: column,
                          order:
                            layout.sort === column && layout.order === "desc"
                              ? "asc"
                              : "desc",
                        } as Layout;
                        void saveLayout(next).catch((e) => setError(e.message));
                      }}
                    >
                      {columns[column]}
                      {layout.sort === column ? (
                        layout.order === "asc" ? (
                          <ArrowUp size={11} />
                        ) : (
                          <ArrowDown size={11} />
                        )
                      ) : null}
                    </button>
                    <span
                      role="separator"
                      aria-label={`Resize ${columns[column]}`}
                      aria-orientation="vertical"
                      tabIndex={0}
                      className="resize-handle"
                      onPointerDown={(e) => {
                        e.preventDefault();
                        resize(column, e.clientX, widths[i]);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
                          e.preventDefault();
                          void saveLayout({
                            ...layout,
                            widths: {
                              ...layout.widths,
                              [column]: Math.max(
                                80,
                                widths[i] + (e.key === "ArrowRight" ? 16 : -16),
                              ),
                            },
                          }).catch((err) => setError(err.message));
                        }
                      }}
                    />
                  </th>
                ))}
              </>
            </tr>
          </thead>
          <tbody>
            {start > 0 && (
              <tr className="spacer" aria-hidden="true">
                <td
                  colSpan={visibleColumns.length + 1}
                  style={{ height: start * rowHeight }}
                />
              </tr>
            )}
            {rows.map((event, index) => (
              <tr
                key={`${event.id}-${start + index}`}
                aria-rowindex={start + index + 2}
                onDoubleClick={() => {
                  rememberResults(event);
                  navigate(eventURL(event));
                }}
              >
                <td>
                  <a
                    href={eventURL(event)}
                    className="row-detail-button"
                    title="View event details"
                    aria-label={`View event ${event.id}`}
                    onClick={(e) => {
                      rememberResults(event);
                      if (!e.metaKey && !e.ctrlKey) {
                        e.preventDefault();
                        navigate(eventURL(event));
                      }
                    }}
                  >
                    <ChevronRight size={14} />
                  </a>
                </td>
                {visibleColumns.map((column) => (
                  <td key={column} title={valueText(event, column)}>
                    {["action", "parse_status"].includes(column) ? (
                      <button
                        className="cell-filter"
                        onClick={() =>
                          setContext({ column, value: event[column] })
                        }
                      >
                        <Status value={event[column]} />
                      </button>
                    ) : fields.some((f) => f.column === column) &&
                      event[column] !== "" &&
                      event[column] != null ? (
                      <button
                        className={`cell-filter ${column.endsWith("_ip") ? "ip-value" : ""}`}
                        onClick={() =>
                          setContext({ column, value: event[column] })
                        }
                      >
                        {valueText(event, column)}
                      </button>
                    ) : (
                      <span
                        className={column.endsWith("_at") ? "timestamp" : ""}
                      >
                        {valueText(event, column)}
                      </span>
                    )}
                  </td>
                ))}
              </tr>
            ))}
            {result && end < result.events.length && (
              <tr className="spacer" aria-hidden="true">
                <td
                  colSpan={visibleColumns.length + 1}
                  style={{ height: (result.events.length - end) * rowHeight }}
                />
              </tr>
            )}
          </tbody>
        </table>
        {!result && busy ? (
          <Loading label="Searching firewall logs…" />
        ) : result?.events.length === 0 && !error ? (
          <EmptyLogCategory
            type={type}
            range={range}
            filtered={!!query}
            busy={busy}
            widen={() => setRange("30d")}
            navigate={navigate}
          />
        ) : !result && !busy && !error ? (
          <Empty title="Ready to search">
            <p>Select a time range and apply a filter.</p>
          </Empty>
        ) : null}
      </div>
      <div className="table-footer">
        <div>
          <span className="footer-count">
            {formatNumber(result?.events.length)} events loaded
          </span>
          {result && <span>Query {formatNumber(result.elapsed_ms)} ms</span>}
          {lastRefresh && (
            <span>Updated {new Date(lastRefresh).toLocaleTimeString()}</span>
          )}
        </div>
        <div>
          <span className="muted" role="status" aria-label="Log refresh status">
            {paused
              ? "Paused"
              : intervalSeconds === 0
                ? "Manual refresh"
                : scrollTop > 0
                  ? "Refresh held while browsing"
                  : `Live · every ${intervalSeconds === 60 ? "minute" : `${intervalSeconds}s`}`}
          </span>
          {result?.next_cursor && (
            <button disabled={busy} onClick={() => void search(true)}>
              {busy ? "Loading…" : "Load next 200"}
              <ChevronRight size={13} />
            </button>
          )}
        </div>
      </div>
      <div className="ingest-strip">
        <span>RECEIVER</span>
        <span>
          Received <b>{formatNumber(stats?.messages_received)}</b>
        </span>
        <span>
          Inserted <b>{formatNumber(stats?.events_inserted)}</b>
        </span>
        <button onClick={() => navigate("/logs/parsing")}>
          Parse failures{" "}
          <b className={stats?.parse_failures ? "text-danger" : ""}>
            {formatNumber(stats?.parse_failures)}
          </b>
        </button>
        <span>
          Dropped{" "}
          <b className={stats?.messages_dropped ? "text-danger" : ""}>
            {formatNumber(stats?.messages_dropped)}
          </b>
        </span>
        <span>
          Spool <b>{bytes(stats?.spool_bytes)}</b>
        </span>
        <button
          className="strip-diagnostics"
          onClick={() => navigate("/administration/diagnostics")}
        >
          <SlidersHorizontal size={12} />
          Diagnostics
        </button>
      </div>
      {modal === "builder" && (
        <FilterBuilder
          fields={fields}
          query={draft}
          onAdd={(q) => {
            setDraft(q);
            setQuery(q);
          }}
          onClose={() => setModal(null)}
        />
      )}
      {modal === "columns" && (
        <ColumnEditor
          layout={layout}
          onSave={saveLayout}
          onClose={() => setModal(null)}
        />
      )}
      {modal === "save" && (
        <SaveFilter
          initial={filter}
          onSaved={() => setNotice("Filter saved to your account.")}
          onClose={() => setModal(null)}
        />
      )}
      {(modal === "load" || savedOpen) && (
        <SavedFilters
          canWrite={canWrite}
          onLoad={loadFilter}
          onClose={() => {
            setModal(null);
            closeSaved();
          }}
        />
      )}
      {context && (
        <Modal
          title={`Filter by ${columns[context.column]}`}
          onClose={() => setContext(undefined)}
        >
          <div className="code-preview">{String(context.value)}</div>
          <label>
            Combine with current filter
            <select
              value={connector}
              onChange={(e) => setConnector(e.target.value)}
            >
              <option value="and">AND</option>
              <option value="or">OR</option>
            </select>
          </label>
          <div className="modal-actions">
            <button onClick={() => setContext(undefined)}>Cancel</button>
            {field && (
              <>
                <button
                  onClick={() => {
                    void apply(
                      combine(
                        draft,
                        buildClause(field.alias, "neq", String(context.value)),
                        connector,
                      ),
                    );
                    setContext(undefined);
                  }}
                >
                  Exclude
                </button>
                <button
                  className="primary"
                  onClick={() => {
                    void apply(
                      combine(
                        draft,
                        buildClause(
                          field.alias,
                          field.type === "ip" ? "in" : "eq",
                          String(context.value),
                        ),
                        connector,
                      ),
                    );
                    setContext(undefined);
                  }}
                >
                  Include
                </button>
              </>
            )}
          </div>
          {!field && (
            <p className="muted">
              This field is available in event details but is not a supported
              filter attribute.
            </p>
          )}
        </Modal>
      )}
      {modal === "export" && (
        <Modal title="Export CSV" onClose={() => setModal(null)}>
          <p className="muted">
            Export the selected columns using the last successful search’s
            filter, time range and sort order.
          </p>
          <div className="export-options">
            <button
              disabled={!result}
              onClick={() => {
                saveBlob(
                  new Blob([visibleCSV(enriched, visibleColumns)], {
                    type: "text/csv;charset=utf-8",
                  }),
                  `captains-log-${type}-visible.csv`,
                );
                setNotice(
                  `${result?.events.length || 0} loaded rows exported.`,
                );
                setModal(null);
              }}
            >
              <Download size={18} />
              <span>
                <strong>Export loaded rows</strong>
                <small>
                  {formatNumber(result?.events.length)} rows currently loaded in
                  the table
                </small>
              </span>
            </button>
            <button
              disabled={
                !snapshot.current ||
                (!!job &&
                  !["completed", "complete", "failed", "error"].includes(
                    job.status,
                  ))
              }
              onClick={async () => {
                try {
                  const s = snapshot.current!;
                  const exportColumns = visibleColumns.filter(
                    (c) => !c.endsWith("_hostname"),
                  );
                  setJob(
                    await api<ExportJob>(
                      "/api/exports",
                      json("POST", {
                        query: s.query,
                        log_type: type,
                        ...s.bounds,
                        columns: exportColumns,
                        sort: s.sort,
                        order: s.order,
                      }),
                    ),
                  );
                } catch (e) {
                  setError((e as Error).message);
                }
              }}
            >
              <Download size={18} />
              <span>
                <strong>Export all matching rows</strong>
                <small>
                  Background job streamed to temporary appliance storage
                </small>
              </span>
            </button>
          </div>
          {resolve && (
            <div className="notice">
              Loaded-row exports include resolved hostnames. Background exports
              include original IPs; DNS enrichment is a separate cache.
            </div>
          )}
          {job && (
            <div className="export-progress">
              <Status value={job.status} />
              <p>
                {formatNumber(job.rows)} rows · {bytes(job.bytes)}
              </p>
              {job.error && <ErrorNotice>{job.error}</ErrorNotice>}
              {["completed", "complete"].includes(job.status) && (
                <button
                  className="primary"
                  onClick={() =>
                    void download(
                      `/api/exports/${encodeURIComponent(job.id)}/download-ticket`,
                      `captains-log-${type}-${job.id}.csv`,
                    ).catch((e) => setError(e.message))
                  }
                >
                  <Download size={14} />
                  Download CSV
                </button>
              )}
            </div>
          )}
        </Modal>
      )}
    </div>
  );
}
