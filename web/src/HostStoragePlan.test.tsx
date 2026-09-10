import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { APIError } from "./api";
import { bindStoragePlanLifecycle, HostStoragePlan, StoragePlanController, StoragePlanView } from "./HostStoragePlan";
import type { StorageExpansionPlan, StoragePlanState } from "./HostStoragePlan";

const now = Date.parse("2026-09-08T12:00:00Z");
const pool = "11111111-1111-4111-8111-111111111111";
const capabilities = { control: "read_only", execution_available: false, pool_id: pool,
  operations: [{ operation: "storage.grow", planning_available: true, execution_available: false, reason: "execution_not_qualified" }] };
function plan(id = "22222222-2222-4222-8222-222222222222"): StorageExpansionPlan {
  return { id, installation_id: "33333333-3333-4333-8333-333333333333", operation: "storage.grow", parameters: { pool_id: pool },
    resource_revision: "a".repeat(64), issued_at: now / 1000, expires_at: now / 1000 + 90, digest: "b".repeat(64), execution_available: false,
    review: { current_bytes: 1024 ** 4, presented_bytes: 2 * 1024 ** 4, unallocated_disk_bytes: 1024 ** 4,
      stages: ["partition", "luks", "pv", "lv", "xfs"], requires_unlock_credential: true, irreversible: true } };
}
function deferred() {
  let resolve!: (value: unknown) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<unknown>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function render(state: StoragePlanState) {
  return renderToStaticMarkup(<StoragePlanView state={state} onReview={() => {}} onRevalidate={() => {}} />);
}

describe("host storage expansion review", () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(now); });
  afterEach(() => vi.useRealTimers());

  it("stays quiet on entry and is visible only to administrators", () => {
    const transport = vi.fn();
    const controller = new StoragePlanController(transport, () => "session");
    controller.wake();
    expect(transport).not.toHaveBeenCalled();
    expect(controller.getSnapshot().phase).toBe("idle");
    for (const role of ["ANALYST", "VIEWER"] as const) {
      expect(renderToStaticMarkup(<HostStoragePlan user={{ id: "person", name: "Person", role }} />)).toBe("");
    }
    const html = renderToStaticMarkup(<HostStoragePlan user={{ id: "admin", name: "Admin", role: "ADMINISTRATOR" }} />);
    expect(html).toContain("Review expansion");
    expect(html).toContain("Expansion is not enabled in this build.");
    expect(html).not.toContain('role="alert"');
  });

  it("requests fresh capabilities before exactly one explicit plan create", async () => {
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(plan());
    const controller = new StoragePlanController(transport, () => "session");
    const request = controller.review();
    await controller.review(); // A rapid second click does not fill the host journal.
    await request;
    expect(transport.mock.calls.map((call) => call[0])).toEqual(["/api/appliance/capabilities", "/api/appliance/plans"]);
    expect(JSON.parse(transport.mock.calls[1][1].body)).toEqual({ operation: "storage.grow", parameters: { pool_id: pool } });
    expect(transport.mock.calls[1][1].method).toBe("POST");
    expect(transport.mock.calls[1][1].headers).toBeUndefined(); // Browser supplies its real Origin.
    expect(controller.getSnapshot().phase).toBe("ready");
  });

  it("shows capacities, stages, credential need and expiry without identifiers or execution controls", async () => {
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(plan());
    const controller = new StoragePlanController(transport, () => "session");
    await controller.review();
    const html = render(controller.getSnapshot());
    for (const text of ["1 TiB", "2 TiB", "Unallocated on disk", "Data partition", "Encrypted mapping", "Physical volume", "Logical volume", "Filesystem", "unlock credential", "Expires", "irreversible"]) expect(html).toContain(text);
    expect(html).not.toContain(plan().digest);
    expect(html).not.toContain(pool);
    expect(html).not.toContain(plan().id);
    expect(html).not.toMatch(/>\s*(Apply|Execute|Authorize|Start job|Step up)\s*</);
  });

  it("hides prior measurements during lookup and uses only the exact plan reference", async () => {
    const lookup = deferred();
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(plan()).mockReturnValueOnce(lookup.promise);
    const controller = new StoragePlanController(transport, () => "session");
    await controller.review();
    const request = controller.revalidate();
    expect(controller.getSnapshot().phase).toBe("revalidating");
    expect(controller.getSnapshot().plan).toBeUndefined();
    expect(render(controller.getSnapshot())).not.toContain("Current pool capacity");
    expect(transport.mock.calls[2][0]).toBe(`/api/appliance/plans/${plan().id}?digest=${plan().digest}`);
    expect(transport.mock.calls[2][1].method).toBeUndefined();
    lookup.resolve(plan()); await request;
    expect(controller.getSnapshot().phase).toBe("ready");
    expect(transport).toHaveBeenCalledTimes(3);
  });

  it("discards out-of-order creation results and aborts their request signals", async () => {
    const old = deferred();
    const fresh = plan("44444444-4444-4444-8444-444444444444");
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(capabilities).mockResolvedValueOnce(fresh);
    const controller = new StoragePlanController(transport, () => "session");
    const previous = controller.review(); await Promise.resolve();
    controller.wake();
    expect(transport.mock.calls[1][1].signal.aborted).toBe(true);
    await controller.review();
    old.resolve(plan()); await previous;
    expect(controller.getSnapshot().plan?.id).toBe(fresh.id);
  });

  it("cannot create a plan from capabilities returned after a session change", async () => {
    let identity = "session-one";
    const pending = deferred(), transport = vi.fn().mockReturnValue(pending.promise);
    const controller = new StoragePlanController(transport, () => identity);
    const request = controller.review();
    identity = "session-two";
    pending.resolve(capabilities); await request;
    expect(transport).toHaveBeenCalledTimes(1);
    expect(controller.getSnapshot().phase).toBe("unavailable");
    expect(controller.getSnapshot().message).toContain("session changed");
    expect(controller.getSnapshot().plan).toBeUndefined();
  });

  it("clears an existing review immediately when the session changes", async () => {
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(plan());
    const controller = new StoragePlanController(transport, () => "session");
    await controller.review(); controller.sessionChanged();
    expect(controller.getSnapshot().plan).toBeUndefined();
    expect(controller.getSnapshot().canRevalidate).toBe(false);
    expect(controller.getSnapshot().message).toContain("session changed");
  });

  it.each([401, 403, 404, 409, 410, 503])("removes previous success on a lookup error %s", async (status) => {
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(plan())
      .mockRejectedValueOnce(new APIError("The host plan is unavailable. Refresh the host measurements before reviewing again.", status));
    const controller = new StoragePlanController(transport, () => "session");
    await controller.review(); await controller.revalidate();
    expect(controller.getSnapshot().phase).toBe(status === 410 ? "expired" : "unavailable");
    expect(controller.getSnapshot().plan).toBeUndefined();
    expect(controller.getSnapshot().canRevalidate).toBe(false);
    expect(render(controller.getSnapshot())).not.toContain("Current pool capacity");
  });

  it("reports the real unavailable response only after a user requests review", async () => {
    const message = "The host plan is unavailable. Refresh the host measurements before reviewing again.";
    const transport = vi.fn().mockRejectedValue(new APIError(message, 503));
    const controller = new StoragePlanController(transport, () => "session");
    expect(render(controller.getSnapshot())).not.toContain(message);
    await controller.review();
    expect(render(controller.getSnapshot())).toContain(message);
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it.each(["installation_id", "resource_revision"])("rejects a lookup with a changed %s binding", async (field) => {
    const changed = { ...plan(), [field]: field === "installation_id" ? "44444444-4444-4444-8444-444444444444" : "c".repeat(64) };
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(plan()).mockResolvedValueOnce(changed);
    const controller = new StoragePlanController(transport, () => "session");
    await controller.review(); await controller.revalidate();
    expect(controller.getSnapshot().phase).toBe("unavailable");
    expect(controller.getSnapshot().plan).toBeUndefined();
  });

  it("expires at the exact deadline without polling the host", async () => {
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(plan());
    const controller = new StoragePlanController(transport, () => "session");
    const win = Object.assign(new EventTarget(), { setTimeout, clearTimeout }) as unknown as Window;
    const doc = new EventTarget() as unknown as Document;
    const unbind = bindStoragePlanLifecycle(controller, win, doc);
    await controller.review();
    await vi.advanceTimersByTimeAsync(90_000);
    expect(controller.getSnapshot().phase).toBe("expired");
    expect(controller.getSnapshot().plan).toBeUndefined();
    expect(controller.getSnapshot().canRevalidate).toBe(false);
    expect(transport).toHaveBeenCalledTimes(2);
    unbind();
  });

  it.each(["focus", "pageshow", "visibilitychange"])("hides a review on %s and requires explicit lookup to restore it", async (event) => {
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(plan()).mockResolvedValueOnce(plan());
    const controller = new StoragePlanController(transport, () => "session");
    const win = Object.assign(new EventTarget(), { setTimeout, clearTimeout }) as unknown as Window;
    const doc = new EventTarget() as unknown as Document;
    const unbind = bindStoragePlanLifecycle(controller, win, doc);
    await controller.review();
    (event === "visibilitychange" ? doc : win).dispatchEvent(new Event(event));
    expect(controller.getSnapshot().phase).toBe("unavailable");
    expect(controller.getSnapshot().plan).toBeUndefined();
    expect(controller.getSnapshot().canRevalidate).toBe(true);
    expect(transport).toHaveBeenCalledTimes(2);
    await controller.revalidate();
    expect(controller.getSnapshot().phase).toBe("ready");
    unbind();
  });

  it("never restores expired evidence after delayed browser wake or an in-flight lookup", async () => {
    const pending = deferred();
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(plan()).mockReturnValueOnce(pending.promise);
    const controller = new StoragePlanController(transport, () => "session");
    await controller.review();
    const lookup = controller.revalidate();
    vi.setSystemTime(now + 100_000); controller.wake();
    pending.resolve(plan()); await lookup;
    expect(controller.getSnapshot().phase).toBe("expired");
    expect(controller.getSnapshot().plan).toBeUndefined();
  });

  it("refuses incompatible capability and response shapes without rendering raw paths", async () => {
    for (const result of [{ ...capabilities, execution_available: true }, { ...capabilities, pool_id: "/etc/private" }]) {
      const transport = vi.fn().mockResolvedValue(result);
      const controller = new StoragePlanController(transport, () => "session"); await controller.review();
      expect(transport).toHaveBeenCalledTimes(1);
      expect(controller.getSnapshot().phase).toBe("unavailable");
    }
    const malformed = { ...plan(), review: { ...plan().review, stages: ["/etc/private"] } };
    const transport = vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(malformed);
    const controller = new StoragePlanController(transport, () => "session"); await controller.review();
    expect(controller.getSnapshot().phase).toBe("unavailable");
    expect(render(controller.getSnapshot())).not.toContain("/etc/private");
  });

  it("keeps measured zero and an empty required-stage list explicit", async () => {
    const measured = plan(); measured.review.unallocated_disk_bytes = 0;
    measured.review.stages = []; measured.review.requires_unlock_credential = false;
    const controller = new StoragePlanController(vi.fn().mockResolvedValueOnce(capabilities).mockResolvedValueOnce(measured), () => "session");
    await controller.review();
    const html = render(controller.getSnapshot());
    expect(html).toContain("0 B"); expect(html).toContain("No expansion stages"); expect(html).toContain("No unlock credential");
  });
});
