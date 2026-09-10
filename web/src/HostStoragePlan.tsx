import { useEffect, useMemo, useSyncExternalStore } from "react";
import { ArrowRight, Clock3, HardDrive, KeyRound, LockKeyhole, RefreshCw, ScanSearch, ShieldAlert } from "lucide-react";
import { api, APIError, authSessionSnapshot, json, subscribeAuthSession } from "./api";
import type { User } from "./types";
import { bytes, timestamp } from "./utils";

type Stage = "partition" | "luks" | "pv" | "lv" | "xfs";
const stageOrder: Stage[] = ["partition", "luks", "pv", "lv", "xfs"];
const stageNames: Record<Stage, string> = {
  partition: "Data partition", luks: "Encrypted mapping", pv: "Physical volume",
  lv: "Logical volume", xfs: "Filesystem",
};
export interface StorageExpansionPlan {
  id: string;
  installation_id: string;
  operation: "storage.grow";
  parameters: { pool_id: string };
  resource_revision: string;
  issued_at: number;
  expires_at: number;
  digest: string;
  execution_available: false;
  review: {
    current_bytes: number;
    presented_bytes: number;
    unallocated_disk_bytes: number;
    stages: Stage[];
    requires_unlock_credential: boolean;
    irreversible: true;
  };
}
export interface StoragePlanState {
  phase: "idle" | "loading" | "revalidating" | "ready" | "expired" | "unavailable";
  message: string;
  identity: string;
  plan?: StorageExpansionPlan;
  canRevalidate: boolean;
  expiresAt?: number;
}
type Transport = (path: string, init?: RequestInit) => Promise<unknown>;
type Reference = Pick<StorageExpansionPlan, "id" | "digest" | "expires_at" | "parameters" | "installation_id" | "resource_revision">;
const unavailable = "The host expansion review is unavailable. Request a fresh review when the host planning service is available.";
const sessionChanged = "Your administrator session changed. Request a fresh expansion review.";
const expired = "This expansion review has expired. Request a fresh review of the current storage.";
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const digest = /^[a-f0-9]{64}$/;
const validID = (value: unknown): value is string => typeof value === "string" && uuid.test(value) && value !== "00000000-0000-0000-0000-000000000000";
const object = (value: unknown): Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const count = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

class ReviewFailure extends Error {
  constructor(message: string, readonly phase: "expired" | "unavailable" = "unavailable") { super(message); }
}

function capabilityPool(value: unknown): string {
  const c = object(value);
  const operations = Array.isArray(c.operations) ? c.operations : [];
  const operation = object(operations[0]);
  if (c.control !== "read_only" || c.execution_available !== false || !validID(c.pool_id)
      || operations.length !== 1 || operation.operation !== "storage.grow" || operation.planning_available !== true
      || operation.execution_available !== false || operation.reason !== "execution_not_qualified") throw new ReviewFailure(unavailable);
  return c.pool_id;
}

function checkedPlan(value: unknown, pool: string, now: number, reference?: Reference): StorageExpansionPlan {
  const p = object(value), r = object(p.review), parameters = object(p.parameters);
  if (count(p.expires_at) && p.expires_at * 1000 <= now) throw new ReviewFailure(expired, "expired");
  const stages = Array.isArray(r.stages) ? r.stages : [];
  if (!validID(p.id) || !validID(p.installation_id) || parameters.pool_id !== pool
      || p.operation !== "storage.grow" || p.execution_available !== false
      || typeof p.digest !== "string" || !digest.test(p.digest)
      || typeof p.resource_revision !== "string" || !digest.test(p.resource_revision)
      || !count(p.issued_at) || p.issued_at <= 0 || p.issued_at * 1000 > now + 5000
      || !count(p.expires_at) || p.expires_at - p.issued_at < 30 || p.expires_at - p.issued_at > 300
      || !count(r.current_bytes) || r.current_bytes <= 0 || !count(r.presented_bytes) || r.presented_bytes < r.current_bytes
      || !count(r.unallocated_disk_bytes) || r.unallocated_disk_bytes > r.presented_bytes
      || !Array.isArray(r.stages) || stages.length > 5 || r.irreversible !== true
      || r.requires_unlock_credential !== stages.includes("luks")
      || !stages.every((stage, index) => stageOrder.includes(stage) && (index === 0 || stageOrder.indexOf(stage) > stageOrder.indexOf(stages[index - 1])))
      || reference && (p.id !== reference.id || p.digest !== reference.digest || p.expires_at !== reference.expires_at
        || p.installation_id !== reference.installation_id || p.resource_revision !== reference.resource_revision)) {
    throw new ReviewFailure(unavailable);
  }
  return value as StorageExpansionPlan;
}

function failure(error: unknown): ReviewFailure {
  if (error instanceof ReviewFailure) return error;
  if (error instanceof APIError) {
    if (error.status === 401) return new ReviewFailure("Your administrator session is no longer current. Sign in again before reviewing expansion.");
    if (error.status === 410) return new ReviewFailure(expired, "expired");
    if (error.status === 409) return new ReviewFailure("Host storage changed after this review. Request a fresh expansion review.");
    if (error.status === 403) return new ReviewFailure("This review must be requested from the configured appliance address with an administrator session.");
    if (error.message === "The host plan is unavailable. Refresh the host measurements before reviewing again.") return new ReviewFailure(error.message);
  }
  return new ReviewFailure(unavailable);
}

// This state machine owns only explicit review requests. Hidden references are
// sufficient for lookup; previous measurements are removed on every retry.
export class StoragePlanController {
  private state: StoragePlanState;
  private listeners = new Set<() => void>();
  private request = 0;
  private active?: AbortController;
  private reference?: Reference;
  constructor(private transport: Transport, private identity: () => string, private clock = Date.now) {
    this.state = { phase: "idle", message: "", identity: identity(), canRevalidate: false };
  }
  getSnapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(phase: StoragePlanState["phase"], message = "", plan?: StorageExpansionPlan) {
    this.state = { phase, message, plan, identity: this.identity(), canRevalidate: !!this.reference,
      expiresAt: this.reference ? this.reference.expires_at * 1000 : undefined };
    for (const listener of this.listeners) listener();
  }
  private cancel() { this.request++; this.active?.abort(); this.active = undefined; }
  sessionChanged = () => {
    this.cancel(); this.reference = undefined;
    this.publish("unavailable", sessionChanged);
  };
  tick = () => {
    if (this.state.identity !== this.identity()) { this.sessionChanged(); return; }
    if (this.reference && this.clock() >= this.reference.expires_at * 1000) {
      this.cancel(); this.reference = undefined; this.publish("expired", expired);
    }
  };
  wake = () => {
    this.tick();
    if (this.state.phase === "idle" || this.state.phase === "expired") return;
    this.cancel();
    this.publish("unavailable", this.reference
      ? "This tab was interrupted. Revalidate the review before using these measurements."
      : "This review was interrupted. Request a fresh expansion review.");
  };
  dispose = () => { this.cancel(); this.reference = undefined; };
  review = () => this.load(false);
  revalidate = () => this.load(true);
  private async load(lookup: boolean) {
    this.tick();
    if (this.state.phase === "loading" || this.state.phase === "revalidating") return;
    const reference = lookup ? this.reference : undefined;
    if (lookup && !reference) return;
    this.cancel();
    const request = this.request, identity = this.identity(), active = new AbortController();
    this.active = active;
    if (!lookup) this.reference = undefined;
    this.publish(lookup ? "revalidating" : "loading");
    const current = () => {
      if (request !== this.request || active.signal.aborted) return false;
      if (identity !== this.identity()) { this.sessionChanged(); return false; }
      return true;
    };
    try {
      let result: unknown, pool: string;
      if (reference) {
        pool = reference.parameters.pool_id;
        result = await this.transport(`/api/appliance/plans/${encodeURIComponent(reference.id)}?digest=${encodeURIComponent(reference.digest)}`, { signal: active.signal });
      } else {
        const capabilities = await this.transport("/api/appliance/capabilities", { signal: active.signal });
        if (!current()) return;
        pool = capabilityPool(capabilities);
        result = await this.transport("/api/appliance/plans", { ...json("POST", { operation: "storage.grow", parameters: { pool_id: pool } }), signal: active.signal });
      }
      if (!current()) return;
      const plan = checkedPlan(result, pool, this.clock(), reference);
      this.reference = { id: plan.id, digest: plan.digest, parameters: { pool_id: plan.parameters.pool_id }, expires_at: plan.expires_at,
        installation_id: plan.installation_id, resource_revision: plan.resource_revision };
      this.publish("ready", "", plan);
    } catch (error) {
      if (!current()) return;
      const detail = failure(error);
      this.reference = undefined;
      this.publish(detail.phase, detail.message);
    }
  }
}

export function bindStoragePlanLifecycle(controller: StoragePlanController, win: Window, doc: Document) {
  let timer: number | undefined;
  const schedule = () => {
    if (timer !== undefined) win.clearTimeout(timer);
    const expiresAt = controller.getSnapshot().expiresAt;
    if (expiresAt !== undefined) timer = win.setTimeout(() => { controller.tick(); schedule(); }, Math.max(0, expiresAt - Date.now()));
  };
  const unsubscribe = controller.subscribe(schedule);
  win.addEventListener("focus", controller.wake);
  win.addEventListener("pageshow", controller.wake);
  doc.addEventListener("visibilitychange", controller.wake);
  schedule();
  return () => {
    if (timer !== undefined) win.clearTimeout(timer);
    unsubscribe();
    win.removeEventListener("focus", controller.wake);
    win.removeEventListener("pageshow", controller.wake);
    doc.removeEventListener("visibilitychange", controller.wake);
  };
}

export function HostStoragePlan({ user }: { user: User }) {
  return user.role === "ADMINISTRATOR" ? <AdministratorReview key={user.id} user={user} /> : null;
}
function AdministratorReview({ user }: { user: User }) {
  const controller = useMemo(() => new StoragePlanController(api, () => `${user.id}:${authSessionSnapshot()}`), [user.id]);
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  useEffect(() => {
    const unsubscribe = subscribeAuthSession(controller.sessionChanged);
    const unbind = bindStoragePlanLifecycle(controller, window, document);
    return () => { unsubscribe(); unbind(); controller.dispose(); };
  }, [controller]);
  return <StoragePlanView state={state} onReview={controller.review} onRevalidate={controller.revalidate} />;
}

export function StoragePlanView({ state, onReview, onRevalidate }: {
  state: StoragePlanState; onReview: () => void; onRevalidate: () => void;
}) {
  const busy = state.phase === "loading" || state.phase === "revalidating";
  const plan = state.phase === "ready" && state.plan && state.plan.expires_at * 1000 > Date.now() ? state.plan : undefined;
  return <section className="panel host-storage-plan" aria-labelledby="storage-plan-title" aria-busy={busy}>
    <style>{`.host-storage-plan .plan-head{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;flex-wrap:wrap}.host-storage-plan .plan-head h3{display:flex;align-items:center;gap:9px;margin:0 0 8px}.host-storage-plan .plan-head h3 svg{color:var(--accent)}.host-storage-plan .plan-head p{color:var(--muted);font-size:12px;line-height:1.7;margin:0;max-width:650px}.host-storage-plan .plan-actions{display:flex;gap:8px;flex-wrap:wrap}.host-storage-plan .plan-capacity{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));border:1px solid var(--border);border-radius:4px;margin:20px 0;overflow:hidden}.host-storage-plan .plan-capacity div{padding:18px;background:var(--raised);min-width:0}.host-storage-plan .plan-capacity dt{font-size:11px;color:var(--muted);margin-bottom:9px}.host-storage-plan .plan-capacity dd{margin:0;font:22px var(--mono);color:var(--text)}.host-storage-plan .plan-stages{display:flex;gap:9px;flex-wrap:wrap;list-style:none;padding:0;margin:14px 0 20px}.host-storage-plan .plan-stages li{display:flex;align-items:center;gap:8px;font-size:12px}.host-storage-plan .plan-stage{display:flex;align-items:center;gap:7px;border:1px solid var(--border);padding:8px 10px;border-radius:4px}.host-storage-plan .plan-stage b{color:var(--accent);font:11px var(--mono)}.host-storage-plan .plan-meta{display:flex;gap:18px;flex-wrap:wrap;margin:18px 0;color:var(--muted);font-size:12px}.host-storage-plan .plan-meta span{display:flex;gap:7px;align-items:center}.host-storage-plan .plan-empty{padding:22px 0 10px;color:var(--muted);font-size:12px;line-height:1.8}.host-storage-plan .plan-label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:20px}.host-storage-plan .notice:last-child{margin-bottom:0}`}</style>
    <div className="plan-head">
      <div><h3 id="storage-plan-title"><HardDrive size={18} /> Expansion review</h3>
        <p>Review the storage presented to this appliance and the host stages needed to use additional capacity.</p></div>
      <div className="plan-actions">
        {state.canRevalidate && <button disabled={busy} onClick={onRevalidate}><RefreshCw size={14} className={state.phase === "revalidating" ? "spin" : ""} /> Revalidate</button>}
        <button className="primary" disabled={busy} onClick={onReview}><ScanSearch size={15} />{state.phase === "loading" ? "Reviewing expansion…" : "Review expansion"}</button>
      </div>
    </div>
    <div className="notice"><LockKeyhole size={16} /><span><strong>Expansion is not enabled in this build.</strong> This review does not change storage or authorize an expansion.</span></div>
    {busy && <p role="status" className="plan-empty">{state.phase === "revalidating" ? "Checking this review against the current host storage…" : "Requesting current host capabilities and a storage review…"}</p>}
    {state.phase === "idle" && <p className="plan-empty">Start a review to see current capacity, available disk space and any required expansion stages. No review has been requested.</p>}
    {(state.phase === "expired" || state.phase === "unavailable") && <div className={`notice ${state.phase === "expired" ? "warning" : "error"}`} role="status"><ShieldAlert size={16} /><span>{state.message}</span></div>}
    {plan && <>
      <dl className="plan-capacity">
        <div><dt>Current pool capacity</dt><dd>{bytes(plan.review.current_bytes)}</dd></div>
        <div><dt>Presented disk capacity</dt><dd>{bytes(plan.review.presented_bytes)}</dd></div>
        <div><dt>Unallocated on disk</dt><dd>{bytes(plan.review.unallocated_disk_bytes)}</dd></div>
      </dl>
      <p className="plan-label">Required host stages</p>
      {plan.review.stages.length ? <ol className="plan-stages">{plan.review.stages.map((stage, index) => <li key={stage}>
        <span className="plan-stage"><b>{String(index + 1).padStart(2, "0")}</b>{stageNames[stage]}</span>
        {index < plan.review.stages.length - 1 && <ArrowRight size={13} aria-hidden="true" />}
      </li>)}</ol> : <p className="plan-empty">No expansion stages are required by this review.</p>}
      <div className="plan-meta">
        <span><KeyRound size={15} />{plan.review.requires_unlock_credential ? "An unlock credential would be required" : "No unlock credential is required by these stages"}</span>
        <span><Clock3 size={15} />Expires <time dateTime={new Date(plan.expires_at * 1000).toISOString()}>{timestamp(new Date(plan.expires_at * 1000).toISOString())}</time></span>
      </div>
      <p className="notice warning"><ShieldAlert size={16} /><span>Storage expansion is irreversible. If enabled in a future build, completing these stages would permanently change the storage layout. No changes have been made by this review.</span></p>
    </>}
  </section>;
}
