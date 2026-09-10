import { chromium, expect } from "@playwright/test";
import path from "node:path";
import { privateDir, baseURL } from "./local-auth.mjs";
const browser = await chromium.launch({
  headless: true,
  channel: process.env.NEBULALOG_E2E_CHANNEL || "chrome",
});
try {
  const context = await browser.newContext({
    storageState: path.join(privateDir, "browser-state.json"),
  });
  const page = await context.newPage();
  await page.goto(`${baseURL}/logs/traffic`);
  await page.getByLabel("Filter query").waitFor();
  await page.getByRole("button", { name: "Pause", exact: true }).click();
  const sort = page.getByRole("button", { name: "Receive Time", exact: true });
  const heading = page.locator("th").filter({ has: sort });
  await expect(heading).toHaveAttribute("aria-sort", /ascending|descending/);
  const original = await heading.getAttribute("aria-sort");
  await sort.click();
  const target = original === "ascending" ? "descending" : "ascending";
  await expect(heading).toHaveAttribute("aria-sort", target);
  const name = `E2E sort-order ${Date.now()}`;
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByLabel("Name", { exact: true }).fill(name);
  const response = page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname === "/api/filters" &&
      r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Save filter", exact: true }).click();
  const created = await (await response).json();
  if (created.order !== (target === "ascending" ? "asc" : "desc"))
    throw new Error("Saved order was not persisted");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await sort.click();
  await expect(heading).toHaveAttribute("aria-sort", original);
  await page.getByRole("button", { name: "Load", exact: true }).click();
  await page.getByLabel("Find saved filters").fill(name);
  const article = page
    .getByRole("article")
    .filter({ has: page.getByRole("heading", { name, exact: true }) });
  await article.getByRole("button", { name: "Load", exact: true }).click();
  await expect(heading).toHaveAttribute("aria-sort", target);
  await sort.click();
  await expect(heading).toHaveAttribute("aria-sort", original);
  await page.getByRole("button", { name: "Load", exact: true }).click();
  await page.getByLabel("Find saved filters").fill(name);
  await article
    .getByRole("button", { name: `Delete ${name}`, exact: true })
    .click();
  await page
    .getByRole("button", { name: "Delete filter", exact: true })
    .click();
  await expect(article).not.toBeVisible();
  console.log(
    JSON.stringify({
      savedSortOrderPersisted: true,
      savedSortOrderRestored: true,
      temporaryFilterDeleted: true,
      originalLayoutRestored: true,
    }),
  );
} finally {
  await browser.close();
}
