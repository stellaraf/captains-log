import { useEffect, useState } from "react";
import { ErrorNotice } from "./components";
import { families } from "./types";

export type RetentionPolicy = {
  revision: number;
  global_days: number;
  per_type: Record<string, number>;
  legacy_alarms_days?: number;
  engine: { mode: string; message?: string };
  status: { state: string; message: string; observed_at?: string };
};
export const retentionFamilies = families.filter(([id]) => id !== "unified" && id !== "alarms")
  .map(([id, label]) => [id, id === "system" ? "System (including System alerts)" : label]);

export function retentionRequest(value: RetentionPolicy, confirmed: boolean) {
  if (!confirmed) throw new Error("Confirm that this policy applies to existing retained events.");
  if (value.engine.mode !== "partition") throw new Error("Retention migration must finish before saving.");
  const valid = (days: number) => Number.isInteger(days) && days >= 1 && days <= 3650;
  if (!valid(value.global_days) || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      Object.entries(value.per_type).some(([id, days]) => !retentionFamilies.some(([kind]) => kind === id) || !valid(days))) {
    throw new Error("Use 1–3,650 whole days for each physical log category.");
  }
  return { expected_revision: value.revision, global_days: value.global_days, per_type: value.per_type, apply_existing: true };
}

export function RetentionPolicyForm({ value, role, onSave }: {
  value: RetentionPolicy; role: string; onSave: (request: ReturnType<typeof retentionRequest>) => Promise<void>;
}) {
  const [draft, setDraft] = useState(value);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  useEffect(() => { setDraft(value); setConfirmed(false); }, [value]);
  const editable = role === "ADMINISTRATOR" && value.engine.mode === "partition";
  const change = (next: RetentionPolicy) => { setDraft(next); setConfirmed(false); setNotice(""); };
  return <section className="retention-section">
    <div className="section-toolbar"><div><h2>Retention policy</h2>
      <p>Changes apply to all retained events and future arrivals, measured from ingestion time. Shorter periods can permanently delete existing logs. Longer periods cannot restore deleted data.</p>
    </div></div>
    {value.engine.mode !== "partition" && <ErrorNotice>Retention migration is incomplete. {value.engine.message}</ErrorNotice>}
    {value.legacy_alarms_days !== undefined && <p role="status">An older System alerts setting of {value.legacy_alarms_days} days was never applied. Review System below; saving replaces that unused setting with the single System policy.</p>}
    <p className="muted">Last cleanup observation: {value.status.state}. {value.status.message} {value.status.observed_at || "No observation yet."} This is a recorded observation; refresh to check progress.</p>
    <form onSubmit={async (event) => {
      event.preventDefault(); setError(""); setNotice("");
      try {
        const request = retentionRequest(draft, confirmed); setBusy(true);
        await onSave(request); setConfirmed(false);
        setNotice("Policy saved for all retained and future events. Physical cleanup continues in bounded batches.");
      } catch (cause) { setError((cause as Error).message); }
      finally { setBusy(false); }
    }}>
      <fieldset disabled={!editable || busy}>
        <div className="global-retention"><label>Global retention
          <input aria-label="Global retention days" type="number" min="1" max="3650" step="1" required value={draft.global_days}
            onChange={(event) => change({ ...draft, global_days: Number(event.target.value) })} />
        </label><span>days</span><div className="presets">
          {[30, 60, 90, 180, 365].map((days) => <button type="button" key={days} className={draft.global_days === days ? "selected" : ""}
            onClick={() => change({ ...draft, global_days: days })}>{days}d</button>)}
        </div></div>
        <div className="retention-grid">{retentionFamilies.map(([id, label]) => <label key={id}><span>{label}</span><div>
          <input type="number" min="1" max="3650" step="1" aria-label={`${label} retention days`} placeholder={String(draft.global_days)} value={draft.per_type[id] ?? ""}
            onChange={(event) => { const per_type = { ...draft.per_type }; if (event.target.value === "") delete per_type[id]; else per_type[id] = Number(event.target.value); change({ ...draft, per_type }); }} /><span>days</span>
        </div></label>)}</div>
        <p className="muted">Blank categories use the global policy. System alerts share System retention. DNS events keep DNS retention when also shown in Threat. Search hides expired rows immediately; storage is reclaimed after complete UTC days expire and background cleanup finishes.</p>
        {role === "ADMINISTRATOR" && <label><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} required /> I understand this applies to existing retained events and permits permanent deletion.</label>}
      </fieldset>
      {error && <ErrorNotice>{error}</ErrorNotice>}
      {notice && <div role="status" className="notice success">{notice}</div>}
      {role === "ADMINISTRATOR" && <button className="primary" disabled={!editable || !confirmed || busy}>{busy ? "Saving…" : "Save retention policy"}</button>}
    </form>
  </section>;
}
