import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";
const base = path.resolve("../.local");
const browser = await chromium.launch({ headless: true, channel: "chrome" });
const context = await browser.newContext({
  storageState: path.join(base, "browser-state.json"),
  acceptDownloads: true,
});
const page = await context.newPage();
await page.goto("http://127.0.0.1:18080/logs/traffic");
await page.getByLabel("Filter query").waitFor();
await page.getByRole("button", { name: "Export CSV", exact: true }).click();
await page.getByRole("button", { name: /Export all matching rows/ }).click();
await page
  .getByRole("button", { name: "Download CSV", exact: true })
  .waitFor({ timeout: 30000 });
const waiting = page.waitForEvent("download");
await page.getByRole("button", { name: "Download CSV", exact: true }).click();
const download = await waiting;
const target = path.join(base, "browser-export.csv");
await download.saveAs(target);
fs.chmodSync(target, 0o600);
const text = fs.readFileSync(target, "utf8");
console.log(
  JSON.stringify({
    nativeCSVDownload: true,
    bytes: fs.statSync(target).size,
    lines: text.trimEnd().split("\n").length,
    headersValid: text.startsWith("received_at,"),
  }),
);
await browser.close();
