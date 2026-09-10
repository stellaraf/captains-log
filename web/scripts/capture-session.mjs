import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";
const base = path.resolve("../.local");
const browser = await chromium.launch({ headless: true, channel: "chrome" });
const context = await browser.newContext({
  storageState: path.join(base, "browser-state.json"),
  viewport: { width: 1560, height: 1000 },
});
const page = await context.newPage();
let captured = false;
page.on("request", (request) => {
  const auth = request.headers().authorization;
  if (
    auth?.startsWith("Bearer ") &&
    new URL(request.url()).origin === "http://127.0.0.1:18080"
  ) {
    fs.writeFileSync(path.join(base, "test-access-token"), auth.slice(7), {
      mode: 0o600,
    });
    captured = true;
  }
});
await page.goto("http://127.0.0.1:18080/logs/traffic");
await page.getByLabel("Filter query").waitFor();
await page.waitForTimeout(1000);
await page.screenshot({ path: path.join(base, "ui.png"), fullPage: true });
console.log(
  JSON.stringify({
    authenticated: captured,
    alerts: await page.getByRole("alert").allTextContents(),
    loaded: await page.locator(".footer-count").textContent(),
  }),
);
await browser.close();
