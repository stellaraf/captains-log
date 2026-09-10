import { chromium, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { privateDir, baseURL } from "./local-auth.mjs";
const browser = await chromium.launch({
  headless: true,
  channel: process.env.NEBULALOG_E2E_CHANNEL || "chrome",
});
try {
  const context = await browser.newContext({
    storageState: path.join(privateDir, "browser-state.json"),
    viewport: { width: 1560, height: 1000 },
  });
  const page = await context.newPage();
  const failures = [];
  page.on("pageerror", (e) => failures.push(e.name));
  let current;
  page.on("response", async (response) => {
    if (response.url().includes("/api/logs?") && response.status() === 200)
      try {
        current = await response.json();
      } catch {}
  });
  page.on("request", (request) => {
    const auth = request.headers().authorization;
    if (
      auth?.startsWith("Bearer ") &&
      new URL(request.url()).origin === baseURL
    )
      fs.writeFileSync(
        path.join(privateDir, "test-access-token"),
        auth.slice(7),
        { mode: 0o600 },
      );
  });
  await page.goto(`${baseURL}/logs/traffic`);
  await page.getByLabel("Filter query").waitFor();
  await page.getByRole("button", { name: "Pause", exact: true }).click();
  await expect
    .poll(() => current?.events.length || 0, { timeout: 15000 })
    .toBeGreaterThan(0);
  await page.screenshot({
    path: path.join(privateDir, "ui.png"),
    fullPage: true,
  });
  const first = current.events[0];
  const details = page.getByRole("link", {
    name: `View event ${first.id}`,
    exact: true,
  });
  const initialRow = page.locator("tbody tr").filter({ has: details });
  await expect
    .poll(() =>
      initialRow.evaluate((el) =>
        Math.round(el.getBoundingClientRect().height),
      ),
    )
    .toBe(32);
  const visibleRows = await page.locator(".table-scroll").evaluate((el) => {
    const box = el.getBoundingClientRect();
    const header = el.querySelector("thead").getBoundingClientRect();
    return [...el.querySelectorAll("tbody tr[aria-rowindex]")].filter((row) => {
      const r = row.getBoundingClientRect();
      return r.top >= header.bottom && r.bottom <= box.bottom;
    }).length;
  });
  await page.locator(".table-scroll").evaluate((el) => (el.scrollTop = 900));
  await expect
    .poll(async () =>
      Number(
        await page
          .locator("tbody tr[aria-rowindex]")
          .first()
          .getAttribute("aria-rowindex"),
      ),
    )
    .toBeGreaterThan(10);
  await page.locator(".table-scroll").evaluate((el) => (el.scrollTop = 0));
  await details.click();
  await expect(
    page.getByRole("heading", { name: "Event details" }),
  ).toBeVisible();
  await page
    .getByRole("link", { name: "Original payload", exact: true })
    .click();
  await expect(page.locator(".full-raw")).toHaveText(first.raw);
  await page.reload();
  await expect(page.locator(".full-raw")).toHaveText(first.raw);
  await page
    .getByRole("link", { name: "Back to log results", exact: true })
    .click();
  const firstRow = page.locator("tbody tr").filter({ has: details });
  await firstRow
    .getByRole("button", { name: first.src_ip, exact: true })
    .first()
    .click();
  const sourceResponse = page.waitForResponse(
    (r) =>
      r.url().includes("/api/logs?") &&
      new URL(r.url()).searchParams.get("query").includes("addr.src"),
  );
  await page.getByRole("button", { name: "Include", exact: true }).click();
  const sourceData = await (await sourceResponse).json();
  if (
    !sourceData.events?.length ||
    !sourceData.events.every((e) => e.src_ip === first.src_ip)
  )
    throw new Error("Source filter result mismatch");
  await expect
    .poll(() => current?.events.every((e) => e.src_ip === first.src_ip), {
      timeout: 15000,
    })
    .toBe(true);
  const clickQuery = await page.getByLabel("Filter query").inputValue();
  if (!clickQuery.includes("addr.src"))
    throw new Error("Click-to-filter did not generate source predicate");
  await page.getByLabel("Filter query").fill("( addr.src in 10.0.0.0/8 )");
  const cidrResponse = page.waitForResponse(
    (r) =>
      r.url().includes("/api/logs?") &&
      new URL(r.url()).searchParams.get("query") ===
        "( addr.src in 10.0.0.0/8 )",
  );
  await page.getByRole("button", { name: "Apply", exact: true }).click();
  if ((await cidrResponse).status() !== 200)
    throw new Error("CIDR search failed");
  await expect(page.getByRole("alert")).not.toBeVisible();
  const dnsResponse = page.waitForResponse((r) =>
    r.url().includes("/api/dns/resolve"),
  );
  await page.getByLabel("Resolve hostnames").check();
  if ((await dnsResponse).status() !== 200)
    throw new Error("DNS worker request failed");
  await expect(
    page.getByRole("button", { name: "Source Hostname", exact: true }),
  ).toBeVisible();
  await page.getByLabel("Filter query").fill("");
  const clearResponse = page.waitForResponse(
    (r) =>
      r.url().includes("/api/logs?") &&
      new URL(r.url()).searchParams.get("query") === "",
  );
  await page.getByRole("button", { name: "Apply", exact: true }).click();
  current = await (await clearResponse).json();
  await expect
    .poll(() => current?.events.length || 0, { timeout: 15000 })
    .toBeGreaterThan(0);
  let pagination = "not_available";
  if (current.next_cursor) {
    await page
      .getByRole("button", { name: "Load next 200", exact: true })
      .click();
    await expect(page.locator(".footer-count")).toHaveText("400 events loaded");
    pagination = "passed";
  }
  await page.getByRole("link", { name: "Firewalls", exact: true }).click();
  await expect(page.locator(".admin-table")).toBeVisible();
  await expect(page.getByRole("alert")).not.toBeVisible();
  console.log(
    JSON.stringify({
      eventDetailsRawMatch: true,
      clickToFilter: true,
      cidrQuery: true,
      dnsColumns: true,
      cursorPagination: pagination,
      dnsWorkerRequest: true,
      firewallInventory: true,
      browserErrors: failures,
      rowHeight: 32,
      visibleRowsAt1000px: visibleRows,
      virtualizationScroll: true,
    }),
  );
} finally {
  await browser.close();
}
