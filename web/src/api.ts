import Keycloak from "keycloak-js";
import type { Config } from "./types";
let keycloak: Keycloak;
let applicationClientID = "";
let sessionGeneration = 0;
let sessionIdentity = "";
const sessionListeners = new Set<() => void>();

// UI invalidation only. Claims stay private in memory; server authorization is
// still required for every request. Ordinary token refresh keeps this stable.
export function authSessionSnapshot() {
  return sessionGeneration;
}
export function subscribeAuthSession(listener: () => void) {
  sessionListeners.add(listener);
  return () => { sessionListeners.delete(listener); };
}
function invalidateAuthSession() {
  sessionGeneration++;
  for (const listener of sessionListeners) listener();
}
function synchronizeAuthSession() {
  const claims = keycloak?.tokenParsed;
  const text = (value: unknown) => typeof value === "string" ? value : "";
  const client = applicationClientID || keycloak?.clientId || "";
  const declaredRoles = claims?.resource_access?.[client]?.roles;
  const roles = Array.isArray(declaredRoles)
    ? [...new Set(declaredRoles.filter((role): role is string => typeof role === "string"))].sort()
    : [];
  const identity = JSON.stringify([keycloak?.authenticated === true,
    text(claims?.iss), text(claims?.sub), text(claims?.sid) || text(claims?.session_state),
    text(claims?.azp), client, roles]);
  if (identity !== sessionIdentity) {
    sessionIdentity = identity;
    invalidateAuthSession();
  }
}
export async function initializeAuth(): Promise<Config> {
  const r = await fetch("/api/config", { cache: "no-store" });
  if (!r.ok)
    throw new Error(
      "Unable to read appliance configuration. Verify that the API is running.",
    );
  const config: Config = await r.json();
  if (!config.auth?.url || !config.auth.realm || !config.auth.client_id)
    throw new Error(
      "Keycloak authentication is not configured. An administrator must configure the appliance before sign-in.",
    );
  applicationClientID = config.auth.client_id;
  keycloak = new Keycloak({
    url: config.auth.url,
    realm: config.auth.realm,
    clientId: config.auth.client_id,
  });
  keycloak.onAuthSuccess = synchronizeAuthSession;
  keycloak.onAuthRefreshSuccess = synchronizeAuthSession;
  keycloak.onAuthLogout = invalidateAuthSession;
  keycloak.onAuthError = invalidateAuthSession;
  keycloak.onAuthRefreshError = invalidateAuthSession;
  try {
    await keycloak.init({
      onLoad: "login-required",
      pkceMethod: "S256",
      checkLoginIframe: false,
      flow: "standard",
    });
    synchronizeAuthSession();
  } catch (error) {
    invalidateAuthSession();
    throw error;
  }
  return config;
}
export class APIError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export async function authenticatedFetch(path: string, init: RequestInit = {}) {
  if (!keycloak?.authenticated) {
    invalidateAuthSession();
    throw new APIError("Your session has expired. Sign in again.", 401);
  }
  try {
    await keycloak.updateToken(30);
    synchronizeAuthSession();
  } catch {
    invalidateAuthSession();
    await keycloak.login();
    throw new APIError("Sign-in required.", 401);
  }
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${keycloak.token}`);
  if (init.body) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...init, headers, cache: "no-store" });
  if (response.status === 401) {
    invalidateAuthSession();
    await keycloak.login();
    throw new APIError("Sign-in required.", 401);
  }
  if (!response.ok) {
    let detail = "The request could not be completed. Please retry.";
    try {
      const body = await response.json();
      if (typeof body.error === "string") detail = body.error;
    } catch {
      /* Never expose upstream HTML/database bodies. */
    }
    throw new APIError(detail, response.status);
  }
  return response;
}
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const r = await authenticatedFetch(path, init);
  if (r.status === 204) return undefined as T;
  return r.json();
}
export function json(method: string, body: unknown): RequestInit {
  return { method, body: JSON.stringify(body) };
}
export function signOut() {
  invalidateAuthSession();
  return keycloak.logout({ redirectUri: location.origin });
}
export async function download(path: string, filename: string) {
  const { url } = await api<{ url: string }>(path, { method: "POST" });
  const target = new URL(url, location.origin);
  if (
    target.origin !== location.origin ||
    !target.pathname.startsWith("/api/downloads/")
  )
    throw new Error("Invalid download destination.");
  const link = document.createElement("a");
  link.href = target.href;
  link.download = filename;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
}
export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
