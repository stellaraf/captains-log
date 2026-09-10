import { test, expect } from "@playwright/test";

// These checks use real authenticated API responses; only their delivery timing is controlled.
test.beforeEach(async ({ page }) => {
  test.skip(!process.env.NEBULALOG_E2E_STORAGE_STATE, "Requires a real enrolled Keycloak session.");
  await page.clock.install();
  const initial = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/logs");
  await page.goto("/logs/traffic");
  expect((await initial).ok()).toBeTruthy();
  await expect(page.getByLabel("Auto-refresh interval")).toBeVisible();
  await expect(page.getByLabel("Refresh logs", { exact: true })).toBeEnabled();
});

test("refresh frequency persists; pause holds results, manual refresh works, resume refreshes immediately", async ({ page }) => {
  const frequency = page.getByLabel("Auto-refresh interval");
  const status = page.getByRole("status", { name: "Log refresh status" });
  await frequency.selectOption("30");
  if (await page.getByRole("button", { name: "Resume", exact: true }).isVisible())
    await page.getByRole("button", { name: "Resume", exact: true }).click();
  await page.getByRole("button", { name: "Pause", exact: true }).click();
  await expect(status).toHaveText("Paused");
  let logRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/logs") logRequests++;
  });
  await page.clock.fastForward(61000);
  expect(logRequests).toBe(0);
  const manualResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/logs");
  await page.getByLabel("Refresh logs", { exact: true }).click();
  expect((await manualResponse).ok()).toBeTruthy();
  await expect(status).toHaveText("Paused");
  const resumedResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/logs");
  await page.getByRole("button", { name: "Resume", exact: true }).click();
  expect((await resumedResponse).ok()).toBeTruthy();
  await expect(status).toHaveText("Live · every 30s");
  await expect(page.getByLabel("Refresh logs", { exact: true })).toBeEnabled();
  const beforeInterval = logRequests;
  const scheduledResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/logs");
  await page.clock.fastForward(30000);
  expect((await scheduledResponse).ok()).toBeTruthy();
  expect(logRequests).toBe(beforeInterval + 1);
  await page.getByRole("button", { name: "Pause", exact: true }).click();
  await page.reload();
  await expect(frequency).toHaveValue("30");
  await expect(status).toHaveText("Paused");
  await page.getByRole("link", { name: "System", exact: true }).click();
  await expect(frequency).toHaveValue("30");
  await expect(status).toHaveText("Paused");
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(frequency).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
});

test("pause cancels an in-flight automatic refresh without replacing displayed rows", async ({ page }) => {
  const frequency = page.getByLabel("Auto-refresh interval");
  await frequency.selectOption("5");
  if (await page.getByRole("button", { name: "Resume", exact: true }).isVisible()) {
    const response = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/logs");
    await page.getByRole("button", { name: "Resume", exact: true }).click();
    await response;
  }
  await expect(page.getByLabel("Refresh logs", { exact: true })).toBeEnabled();
  const before = await page.locator("tbody").innerText();
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  let responseReady!: () => void;
  const ready = new Promise<void>((resolve) => { responseReady = resolve; });
  let deliveryFinished!: () => void;
  const delivered = new Promise<void>((resolve) => { deliveryFinished = resolve; });
  await page.route("**/api/logs?*", async (route) => {
    const response = await route.fetch();
    responseReady();
    await held;
    await route.fulfill({ response }).catch(() => { /* The paused request was aborted. */ });
    deliveryFinished();
  });
  await page.clock.fastForward(5000);
  await ready;
  await page.getByRole("button", { name: "Pause", exact: true }).click();
  release();
  await delivered;
  await expect(page.getByRole("status", { name: "Log refresh status" })).toHaveText("Paused");
  await expect(page.getByLabel("Refresh logs", { exact: true })).toBeEnabled();
  expect(await page.locator("tbody").innerText()).toBe(before);
  await expect(page.getByRole("alert")).not.toBeVisible();
});
