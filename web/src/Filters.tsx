import { useEffect, useState } from "react";
import { ArrowDown, ArrowUp, Copy, Star, Trash2 } from "lucide-react";
import { api, json } from "./api";
import { columns } from "./types";
import type { Field, Layout, SavedFilter } from "./types";
import { buildClause, combine } from "./utils";
import { Modal, ErrorNotice, Loading } from "./components";
export function FilterBuilder({
  fields,
  query,
  onAdd,
  onClose,
}: {
  fields: Field[];
  query: string;
  onAdd: (q: string) => void;
  onClose: () => void;
}) {
  const [alias, setAlias] = useState(fields[0]?.alias || "addr.src");
  const [operator, setOperator] = useState(fields[0]?.operators[0] || "in");
  const [connector, setConnector] = useState("and");
  const [value, setValue] = useState("");
  const [negate, setNegate] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const selected = fields.find((f) => f.alias === alias);
  const generated = combine(
    query,
    buildClause(alias, operator, value, negate),
    connector,
  );
  async function submit() {
    setBusy(true);
    setError("");
    try {
      await api("/api/query/validate", json("POST", { query: generated }));
      onAdd(generated);
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="Add log filter" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <p className="muted">
          Build an expression using the same query engine as the filter bar.
        </p>
        <div className="form-grid">
          <label>
            Connector
            <select
              aria-label="Connector"
              value={connector}
              onChange={(e) => setConnector(e.target.value)}
            >
              <option value="and">AND — match both</option>
              <option value="or">OR — match either</option>
            </select>
          </label>
          <label>
            Attribute
            <select
              aria-label="Attribute"
              value={alias}
              onChange={(e) => {
                setAlias(e.target.value);
                setOperator(
                  fields.find((f) => f.alias === e.target.value)
                    ?.operators[0] || "eq",
                );
              }}
            >
              {fields.map((f) => (
                <option key={f.alias} value={f.alias}>
                  {f.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Operator
            <select
              aria-label="Operator"
              value={operator}
              onChange={(e) => setOperator(e.target.value)}
            >
              {(
                selected?.operators || ["eq", "neq", "in", "not-in", "contains"]
              ).map((op) => (
                <option key={op}>{op}</option>
              ))}
            </select>
          </label>
          <label>
            Value
            <input
              autoFocus
              required
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={
                alias.startsWith("addr.") ? "10.0.0.0/8" : "Enter a value"
              }
            />
          </label>
        </div>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={negate}
            onChange={(e) => setNegate(e.target.checked)}
          />
          Negate this expression
        </label>
        <div className="code-preview">{generated}</div>
        {error && <ErrorNotice>{error}</ErrorNotice>}
        <div className="modal-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy || !fields.length}>
            {busy ? "Validating…" : "Add & apply filter"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
export function ColumnEditor({
  layout,
  onSave,
  onClose,
}: {
  layout: Layout;
  onSave: (v: Layout) => Promise<void>;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState({
    ...layout,
    columns: [...layout.columns],
  });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const all = [
    ...draft.columns,
    ...Object.keys(columns).filter((x) => !draft.columns.includes(x)),
  ];
  function move(key: string, direction: number) {
    const list = [...draft.columns];
    const index = list.indexOf(key);
    const to = index + direction;
    if (to < 0 || to >= list.length) return;
    [list[index], list[to]] = [list[to], list[index]];
    setDraft({ ...draft, columns: list });
  }
  return (
    <Modal title="Customize columns" onClose={onClose}>
      <p className="muted">
        Choose visible columns and their order. Layouts are saved to your
        account for this log category.
      </p>
      <div className="column-options">
        {all.map((key) => (
          <div key={key} className="column-option">
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={draft.columns.includes(key)}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    columns: e.target.checked
                      ? [...draft.columns, key]
                      : draft.columns.filter((c) => c !== key),
                  })
                }
              />
              {columns[key]}
            </label>
            {draft.columns.includes(key) && (
              <span>
                <button
                  className="icon-button"
                  title={`Move ${columns[key]} left`}
                  aria-label={`Move ${columns[key]} left`}
                  onClick={() => move(key, -1)}
                >
                  <ArrowUp size={14} />
                </button>
                <button
                  className="icon-button"
                  title={`Move ${columns[key]} right`}
                  aria-label={`Move ${columns[key]} right`}
                  onClick={() => move(key, 1)}
                >
                  <ArrowDown size={14} />
                </button>
              </span>
            )}
          </div>
        ))}
      </div>
      {error && <ErrorNotice>{error}</ErrorNotice>}
      <div className="modal-actions">
        <button onClick={onClose}>Cancel</button>
        <button
          className="primary"
          disabled={busy || !draft.columns.length}
          onClick={async () => {
            setBusy(true);
            try {
              await onSave(draft);
              onClose();
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Saving…" : "Save layout"}
        </button>
      </div>
    </Modal>
  );
}
export function SaveFilter({
  initial,
  onSaved,
  onClose,
}: {
  initial: SavedFilter;
  onSaved: () => void;
  onClose: () => void;
}) {
  const [filter, setFilter] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <Modal
      title={initial.id ? "Edit saved filter" : "Save filter"}
      onClose={onClose}
    >
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          try {
            await api(
              `/api/filters${initial.id ? `/${encodeURIComponent(initial.id)}` : ""}`,
              json(initial.id ? "PUT" : "POST", filter),
            );
            onSaved();
            onClose();
          } catch (err) {
            setError((err as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Name
          <input
            autoFocus
            required
            maxLength={120}
            value={filter.name}
            onChange={(e) => setFilter({ ...filter, name: e.target.value })}
          />
        </label>
        <label>
          Description
          <textarea
            value={filter.description}
            onChange={(e) =>
              setFilter({ ...filter, description: e.target.value })
            }
          />
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={filter.favorite}
            onChange={(e) =>
              setFilter({ ...filter, favorite: e.target.checked })
            }
          />
          Favorite
        </label>
        <div className="code-preview">
          {filter.query || "All events in selected range"}
        </div>
        {error && <ErrorNotice>{error}</ErrorNotice>}
        <div className="modal-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy}>
            {busy ? "Saving…" : "Save filter"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
export function SavedFilters({
  canWrite,
  onLoad,
  onClose,
}: {
  canWrite: boolean;
  onLoad: (v: SavedFilter) => void;
  onClose: () => void;
}) {
  const [items, setItems] = useState<SavedFilter[]>();
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState<SavedFilter>();
  const [deleting, setDeleting] = useState<SavedFilter>();
  const load = () =>
    api<{ filters: SavedFilter[] }>("/api/filters")
      .then((r) => setItems(r.filters))
      .catch((e) => setError(e.message));
  useEffect(() => {
    void load();
  }, []);
  async function mutate(path: string, method: string, body?: SavedFilter) {
    try {
      await api(path, body ? json(method, body) : { method });
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  if (editing)
    return (
      <SaveFilter
        initial={editing}
        onClose={() => setEditing(undefined)}
        onSaved={() => void load()}
      />
    );
  return (
    <Modal title="Saved filters" onClose={onClose} wide>
      <input
        className="full-width"
        aria-label="Find saved filters"
        placeholder="Find a filter…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />
      {error && <ErrorNotice>{error}</ErrorNotice>}
      {!items ? (
        <Loading />
      ) : (
        <div className="saved-list">
          {items
            .filter((i) =>
              `${i.name} ${i.description}`
                .toLowerCase()
                .includes(search.toLowerCase()),
            )
            .sort((a, b) => Number(b.favorite) - Number(a.favorite))
            .map((item) => (
              <article key={item.id || item.name}>
                <div className="saved-main">
                  <h3>
                    {item.favorite && <Star size={13} fill="currentColor" />}
                    {item.name}
                    {item.builtin && <span className="tag">BUILT-IN</span>}
                  </h3>
                  {item.description && <p>{item.description}</p>}
                  <code>{item.query || "All events"}</code>
                  <small>
                    {item.log_type} · {item.time_range}
                  </small>
                </div>
                <div className="saved-actions">
                  <button
                    onClick={() => {
                      onLoad(item);
                      onClose();
                    }}
                  >
                    Load
                  </button>
                  {canWrite && (
                    <>
                      <button
                        className="icon-button"
                        title="Duplicate filter"
                        aria-label={`Duplicate ${item.name}`}
                        onClick={() =>
                          setEditing({
                            ...item,
                            id: undefined,
                            builtin: false,
                            name: `${item.name} copy`,
                          })
                        }
                      >
                        <Copy size={15} />
                      </button>
                      {!item.builtin && (
                        <>
                          <button
                            className="icon-button"
                            aria-label={`Favorite ${item.name}`}
                            onClick={() =>
                              void mutate(
                                `/api/filters/${encodeURIComponent(item.id!)}`,
                                "PUT",
                                { ...item, favorite: !item.favorite },
                              )
                            }
                          >
                            <Star size={15} />
                          </button>
                          <button onClick={() => setEditing(item)}>Edit</button>
                          <button
                            className="icon-button"
                            aria-label={`Delete ${item.name}`}
                            onClick={() => setDeleting(item)}
                          >
                            <Trash2 size={15} />
                          </button>
                        </>
                      )}
                    </>
                  )}
                </div>
              </article>
            ))}
          {items.length === 0 && <p className="muted">No saved filters yet.</p>}
        </div>
      )}
      {deleting && (
        <div className="notice warning">
          <span>Delete “{deleting.name}”?</span>
          <button onClick={() => setDeleting(undefined)}>Cancel</button>
          <button
            className="danger"
            onClick={async () => {
              await mutate(
                `/api/filters/${encodeURIComponent(deleting.id!)}`,
                "DELETE",
              );
              setDeleting(undefined);
            }}
          >
            Delete filter
          </button>
        </div>
      )}
    </Modal>
  );
}
