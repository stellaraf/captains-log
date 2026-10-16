import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { RefreshCw, ShieldCheck } from "lucide-react";
import { api, authSessionSnapshot, json, subscribeAuthSession } from "./api";
import { ErrorNotice, Loading, Status } from "./components";
import { families } from "./types";
import type { User } from "./types";
import { bytes, formatNumber, timestamp } from "./utils";

export type EmergencyPolicy = {
  revision: number;
  enabled: boolean;
  trigger_percent: number;
  recover_percent: number;
  minimum_days: Record<string, number>;
};
export type EmergencyAction = {
  id: string;
  state: string;
  created_at: string;
  updated_at: string;
  policy_revision: number;
  table_uuid: string;
  partition_id: string;
  log_type: string;
  partition_day: string;
  rows: number;
  bytes_on_disk: number;
  message: string;
};
export type EmergencyState = {
  policy: EmergencyPolicy;
  status: {
    state: string;
    observed_at?: string | null;
    message: string;
    used_percent?: number | null;
    pending?: unknown;
    insert_exclusions?: number;
    exclusion_message?: string;
    maintenance_held?: boolean;
    delivery_held?: boolean;
    maintenance_message?: string;
  };
  recent_actions: EmergencyAction[];
};

const endpoint = "/api/storage/emergency";
const labels: Record<string, string> = Object.fromEntries(families);

export function emergencyObservationFresh(value: EmergencyState["status"], now: number) {
  const at = Date.parse(value.observed_at || "");
  return Number.isFinite(at) && at <= now + 5_000 && now - at <= 120_000;
}

export function EmergencyObservation({ value, now }: { value: EmergencyState["status"]; now: number }) {
  const fresh = emergencyObservationFresh(value, now);
  return <div className="emergency-observation" role="status">
    <div><Status value={fresh ? value.state : "not_observed"} />
      <span className="muted">{value.observed_at ? `Last check ${timestamp(value.observed_at)}` : "No controller observation yet"}</span>
      {fresh && typeof value.used_percent === "number" && Number.isFinite(value.used_percent) &&
        <strong>{value.used_percent.toFixed(1)}% used on the log disk</strong>}
    </div>
    <p>{fresh ? value.message : "A recent controller result is unavailable. Refresh to check whether automatic cleanup is operating."}</p>
    {fresh && value.maintenance_held && <p><strong>Appliance maintenance is active.</strong> {value.maintenance_message ||
      (value.delivery_held ? "Automatic cleanup and log delivery are paused; queued logs are retained." : "Automatic cleanup is paused while the appliance verifies its update.")}</p>}
    {fresh && typeof value.insert_exclusions === "number" && value.insert_exclusions > 0 &&
      <p><strong>{formatNumber(value.insert_exclusions)} unresolved insert reservations.</strong> {value.exclusion_message || "Their affected log partitions are excluded from emergency cleanup until the write outcomes are resolved."}</p>}
  </div>;
}

function EmergencyPanel() {
  const session = useSyncExternalStore(subscribeAuthSession, authSessionSnapshot, authSessionSnapshot);
  const [result, setResult] = useState<{ value: EmergencyState; user: User; session: number }>();
  const [draft, setDraft] = useState<EmergencyPolicy>();
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [refresh, setRefresh] = useState(() => ({ sequence: 0, session }));
  const [now, setNow] = useState(Date.now());
  const generation = useRef(0);
  const saveController = useRef<AbortController | undefined>(undefined);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 5_000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    const current = ++generation.current;
    const controller = new AbortController();
    saveController.current?.abort();
    setResult(undefined);
    setDraft(undefined);
    setAcknowledged(false);
    setBusy(true);
    setSaving(false);
    setError("");
    setNotice("");
    if (session !== refresh.session) {
      setBusy(false);
      setError("Your sign-in session changed. Refresh to load the policy for your current session.");
      return () => { generation.current++; controller.abort(); saveController.current?.abort(); };
    }
    void Promise.all([
      api<EmergencyState>(endpoint, { signal: controller.signal, expectedSession: session }),
      api<User>("/api/me", { signal: controller.signal, expectedSession: session }),
    ]).then(([value, user]) => {
      if (controller.signal.aborted || current !== generation.current || session !== authSessionSnapshot()) return;
      setResult({ value, user, session });
      setDraft(value.policy);
    }).catch((reason: unknown) => {
      if (!controller.signal.aborted && current === generation.current) setError((reason as Error).message);
    }).finally(() => {
      if (current === generation.current) setBusy(false);
    });
    return () => { generation.current++; controller.abort(); saveController.current?.abort(); };
  }, [session, refresh]);
  const value = result?.session === session ? result.value : undefined;
  const policy = value ? draft : undefined;
  const dirty = !!policy && JSON.stringify(policy) !== JSON.stringify(value?.policy);
  const administrator = !!value && result?.user.role === "ADMINISTRATOR";
  function edit(next: EmergencyPolicy) {
    setDraft(next);
    setAcknowledged(false);
    setNotice("");
  }
  async function save() {
    if (!policy || !value || !dirty || !acknowledged || saving || !administrator) return;
    const current = generation.current;
    const controller = new AbortController();
    saveController.current = controller;
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const { revision, ...changes } = policy;
      const saved = await api<EmergencyState>(endpoint, {
        ...json("PUT", { expected_revision: revision, ...changes }), signal: controller.signal, expectedSession: session,
      });
      if (controller.signal.aborted || current !== generation.current || session !== authSessionSnapshot()) return;
      setResult({ value: saved, user: result!.user, session });
      setDraft(saved.policy);
      setAcknowledged(false);
      setNotice(`Emergency policy revision ${saved.policy.revision} saved. The controller applies it on its next check.`);
    } catch (reason) {
      if (!controller.signal.aborted && current === generation.current) {
        setResult(undefined);
        setDraft(undefined);
        setAcknowledged(false);
        setError(`${(reason as Error).message} Refresh to read the current policy before making another change.`);
      }
    } finally {
      if (current === generation.current) setSaving(false);
    }
  }
  return <section className="panel emergency-storage" aria-labelledby="emergency-storage-title">
    <div className="section-toolbar small">
      <div><h3 id="emergency-storage-title"><ShieldCheck size={17} aria-hidden="true" /> Emergency storage protection</h3>
        <p>Reclaim space when the log disk is nearly full. Eligible Traffic days are removed first.</p></div>
      <button disabled={busy || saving} aria-label="Refresh emergency storage protection" onClick={() => {
        setNotice(""); setRefresh((version) => ({ sequence: version.sequence + 1, session }));
      }}><RefreshCw size={14} aria-hidden="true" /> Refresh</button>
    </div>
    {error && <ErrorNotice>{error}</ErrorNotice>}
    {busy && <Loading label="Loading emergency storage policy…" />}
    {value && <EmergencyObservation value={value.status} now={now} />}
    {policy && <form onSubmit={(event) => { event.preventDefault(); void save(); }}>
      <fieldset disabled={!administrator || saving}>
        <legend className="sr-only">Emergency storage policy</legend>
        <label className="emergency-enable"><input type="checkbox" checked={policy.enabled}
          onChange={(event) => edit({ ...policy, enabled: event.target.checked })} />
          Enable automatic emergency cleanup</label>
        <div className="emergency-thresholds">
          <label>Start cleanup at<input type="number" required min="90" max="99"
            aria-label="Emergency cleanup start percentage" value={policy.trigger_percent}
            onChange={(event) => edit({ ...policy, trigger_percent: Number(event.target.value) })} /><span>% used</span></label>
          <label>Stop cleanup at<input type="number" required min="70" max={policy.trigger_percent - 1}
            aria-label="Emergency cleanup stop percentage" value={policy.recover_percent}
            onChange={(event) => edit({ ...policy, recover_percent: Number(event.target.value) })} /><span>% used</span></label>
        </div>
        <p className="muted">Cleanup removes complete days, one at a time, and waits for disk reclamation before proceeding. If protected data or another service consumes the remaining space, cleanup stops and reports the problem.</p>
        <details className="emergency-minimums" open>
          <summary>Minimum ages for emergency deletion</summary>
          <p>Events younger than these ages are protected from emergency cleanup. Your normal retention policy can still expire them sooner. Unknown and unsupported log categories are excluded from emergency cleanup. The System minimum also covers System alerts.</p>
          <div className="retention-grid">
            {Object.entries(policy.minimum_days).map(([family, days]) => <label key={family}>
              <span>{labels[family] || family}</span><div><input type="number" min="1" max="3650" required
                aria-label={`${labels[family] || family} emergency minimum days`} value={days}
                onChange={(event) => edit({ ...policy, minimum_days: { ...policy.minimum_days, [family]: Number(event.target.value) } })} />
                <span>days</span></div>
            </label>)}
          </div>
        </details>
        {administrator && <>
          <label className="emergency-confirm"><input type="checkbox" checked={acknowledged} disabled={!dirty || saving}
            onChange={(event) => setAcknowledged(event.target.checked)} />
            I understand this policy can permanently delete eligible logs before their normal retention expires.</label>
          <div className="emergency-save"><button className="primary" disabled={!dirty || !acknowledged || saving}>
            {saving ? "Saving…" : "Save emergency policy"}</button><span className="muted">Revision {policy.revision}{dirty ? " · Unsaved changes; Refresh discards them" : " · Saved policy"}</span></div>
        </>}
      </fieldset>
      {!administrator && <p className="muted">An administrator can change this policy.</p>}
    </form>}
    {notice && <p className="notice success" role="status">{notice}</p>}
    {value && <div className="emergency-history">
      <h4>Recent cleanup actions</h4>
      {value.recent_actions.length === 0 ? <p className="muted">No emergency deletion has been recorded.</p> :
        <div className="emergency-table-scroll" tabIndex={0} role="region" aria-label="Recent emergency cleanup actions">
          <table><thead><tr><th>Recorded</th><th>Category / day</th><th>State</th><th>Selected rows / size</th><th>Result</th></tr></thead>
            <tbody>{value.recent_actions.map((action) => <tr key={action.id}>
              <td>{timestamp(action.updated_at || action.created_at)}</td>
              <td>{labels[action.log_type] || action.log_type}<br /><span className="mono">{action.partition_day}</span></td>
              <td><Status value={action.state} /></td><td>{formatNumber(action.rows)}<br /><span className="muted">{bytes(action.bytes_on_disk)}</span></td>
              <td>{action.message}<br /><small className="muted">Policy revision {action.policy_revision} · {action.id}</small></td>
            </tr>)}</tbody></table>
        </div>}
    </div>}
  </section>;
}

export function EmergencyStorage() {
  return <EmergencyPanel />;
}
