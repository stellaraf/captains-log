import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const auth = vi.hoisted(() => ({ instance: {} as Record<string, any> }));
vi.mock("keycloak-js", () => ({ default: vi.fn(function () { return auth.instance; }) }));
const configuration = { auth: { url: "https://login.example.test", realm: "nebulalog", client_id: "nebulalog" }, version: "test" };

describe("opaque authentication session generation", () => {
  beforeEach(() => {
    vi.resetModules();
    auth.instance = {
      authenticated: true, token: "never-render-this-token",
      tokenParsed: { iss: "https://login.example.test/realms/nebulalog", sub: "private-subject", sid: "private-session", exp: 1,
        azp: "nebulalog", resource_access: { nebulalog: { roles: ["ADMINISTRATOR", "VIEWER"] } } },
      init: vi.fn().mockResolvedValue(true), updateToken: vi.fn().mockResolvedValue(false),
      login: vi.fn().mockResolvedValue(undefined), logout: vi.fn().mockResolvedValue(undefined),
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(configuration), { status: 200 })));
    vi.stubGlobal("location", { origin: "https://nebulalog.example.test" });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("publishes only an opaque counter and preserves ordinary same-session refresh", async () => {
    const api = await import("./api"); await api.initializeAuth();
    const initial = api.authSessionSnapshot(), listener = vi.fn();
    const unsubscribe = api.subscribeAuthSession(listener);
    auth.instance.token = "new-private-token"; auth.instance.tokenParsed.exp = 2;
    auth.instance.onAuthRefreshSuccess();
    await api.authenticatedFetch("/api/stats");
    expect(api.authSessionSnapshot()).toBe(initial);
    expect(typeof initial).toBe("number"); expect(listener).not.toHaveBeenCalled();
    unsubscribe();
  });

  it.each(["iss", "sub", "sid", "azp"])("invalidates on a signed %s identity change", async (field) => {
    const api = await import("./api"); await api.initializeAuth();
    const initial = api.authSessionSnapshot(), listener = vi.fn(); api.subscribeAuthSession(listener);
    auth.instance.tokenParsed[field] += "-changed"; auth.instance.onAuthRefreshSuccess();
    expect(api.authSessionSnapshot()).toBeGreaterThan(initial); expect(listener).toHaveBeenCalledTimes(1);
    expect(listener.mock.calls[0]).toEqual([]);
  });

  it("invalidates administrator role loss even when the subject and session stay the same", async () => {
    const api = await import("./api"); await api.initializeAuth();
    const initial = api.authSessionSnapshot();
    auth.instance.tokenParsed.resource_access.nebulalog.roles = ["VIEWER"];
    auth.instance.onAuthRefreshSuccess();
    expect(api.authSessionSnapshot()).toBeGreaterThan(initial);
  });

  it("preserves generation for reordered application roles and unrelated client roles", async () => {
    const api = await import("./api"); await api.initializeAuth();
    const initial = api.authSessionSnapshot();
    auth.instance.tokenParsed.resource_access.nebulalog.roles = ["VIEWER", "ADMINISTRATOR", "VIEWER"];
    auth.instance.tokenParsed.resource_access.other = { roles: ["changed"] };
    auth.instance.onAuthRefreshSuccess();
    expect(api.authSessionSnapshot()).toBe(initial);
  });

  it("tracks session_state when sid is absent", async () => {
    delete auth.instance.tokenParsed.sid; auth.instance.tokenParsed.session_state = "first";
    const api = await import("./api"); await api.initializeAuth();
    const initial = api.authSessionSnapshot(); auth.instance.tokenParsed.session_state = "second";
    await api.authenticatedFetch("/api/stats");
    expect(api.authSessionSnapshot()).toBeGreaterThan(initial);
  });

  it("invalidates before logout navigation", async () => {
    const api = await import("./api"); await api.initializeAuth();
    const initial = api.authSessionSnapshot();
    auth.instance.logout.mockImplementation(() => { expect(api.authSessionSnapshot()).toBeGreaterThan(initial); return Promise.resolve(); });
    await api.signOut();
    expect(auth.instance.logout).toHaveBeenCalledTimes(1);
  });

  it.each(["onAuthLogout", "onAuthError", "onAuthRefreshError"])("invalidates on %s", async (callback) => {
    const api = await import("./api"); await api.initializeAuth();
    const initial = api.authSessionSnapshot(); auth.instance[callback]();
    expect(api.authSessionSnapshot()).toBeGreaterThan(initial);
  });

  it("invalidates a 401 before requesting sign-in", async () => {
    const api = await import("./api"); await api.initializeAuth();
    const initial = api.authSessionSnapshot();
    vi.mocked(fetch).mockResolvedValue(new Response("", { status: 401 }));
    auth.instance.login.mockImplementation(() => { expect(api.authSessionSnapshot()).toBeGreaterThan(initial); return Promise.resolve(); });
    await expect(api.authenticatedFetch("/api/appliance/capabilities")).rejects.toMatchObject({ status: 401 });
    expect(auth.instance.login).toHaveBeenCalledTimes(1);
  });

  it("invalidates refresh failure and an already ended session", async () => {
    const api = await import("./api"); await api.initializeAuth();
    const initial = api.authSessionSnapshot(); auth.instance.updateToken.mockRejectedValue(new Error("refresh failed"));
    await expect(api.authenticatedFetch("/api/appliance/capabilities")).rejects.toMatchObject({ status: 401 });
    expect(api.authSessionSnapshot()).toBeGreaterThan(initial);
    const refreshed = api.authSessionSnapshot(); auth.instance.authenticated = false;
    await expect(api.authenticatedFetch("/api/appliance/capabilities")).rejects.toMatchObject({ status: 401 });
    expect(api.authSessionSnapshot()).toBeGreaterThan(refreshed);
  });

  it("allows subscribers to detach without exposing identity fields", async () => {
    const api = await import("./api"); await api.initializeAuth();
    const listener = vi.fn(), unsubscribe = api.subscribeAuthSession(listener);
    unsubscribe(); auth.instance.onAuthError();
    expect(listener).not.toHaveBeenCalled();
    expect(JSON.stringify(api.authSessionSnapshot())).not.toContain("private-");
  });

  it.each(["session", "roles"])("does not dispatch a confirmed PUT when token refresh changes %s", async (change) => {
    const api = await import("./api"); await api.initializeAuth();
    const expectedSession = api.authSessionSnapshot();
    vi.mocked(fetch).mockClear();
    auth.instance.updateToken.mockImplementation(async () => {
      if (change === "session") auth.instance.tokenParsed.sid = "another-session";
      else auth.instance.tokenParsed.resource_access.nebulalog.roles = ["VIEWER"];
      return true;
    });
    await expect(api.authenticatedFetch("/api/storage/emergency", {
      method: "PUT", body: "{}", expectedSession,
    })).rejects.toMatchObject({ status: 409 });
    expect(fetch).not.toHaveBeenCalled();
    expect(auth.instance.login).not.toHaveBeenCalled();
  });

  it("rejects an already invalidated confirmation before refreshing a token", async () => {
    const api = await import("./api"); await api.initializeAuth();
    const expectedSession = api.authSessionSnapshot(); auth.instance.onAuthLogout();
    vi.mocked(fetch).mockClear();
    await expect(api.authenticatedFetch("/api/storage/emergency", {
      method: "PUT", expectedSession,
    })).rejects.toMatchObject({ status: 409 });
    expect(fetch).not.toHaveBeenCalled();
    expect(auth.instance.updateToken).not.toHaveBeenCalled();
  });

  it("permits same-session token renewal without sending the local generation to the server", async () => {
    const api = await import("./api"); await api.initializeAuth();
    const expectedSession = api.authSessionSnapshot();
    vi.mocked(fetch).mockClear();
    auth.instance.updateToken.mockImplementation(async () => { auth.instance.token = "renewed"; auth.instance.tokenParsed.exp++; return true; });
    await api.authenticatedFetch("/api/storage/emergency", { method: "PUT", body: "{}", expectedSession });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(vi.mocked(fetch).mock.calls[0][1]).not.toHaveProperty("expectedSession");
    expect(new Headers(vi.mocked(fetch).mock.calls[0][1]?.headers).get("Authorization")).toBe("Bearer renewed");
  });
});
