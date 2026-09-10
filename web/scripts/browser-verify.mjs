// First-use enrollment (or repeat MFA login) through the real Keycloak UI.
import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";
import { privateDir, passwordLogin, privateJSON, totp } from "./local-auth.mjs";
const browser = await chromium.launch({
  headless: true,
  channel: process.env.NEBULALOG_E2E_CHANNEL || "chrome",
});
try {
  const context = await browser.newContext({
    viewport: { width: 1560, height: 1000 },
  });
  const page = await context.newPage();
  await passwordLogin(page);
  await page.locator("#totp,#otp").waitFor();
  let enrolled = false;
  if (await page.locator("#totp").count()) {
    await page.getByRole("link", { name: "Unable to scan?" }).click();
    const secret = (
      await page.locator("#kc-totp-secret-key").textContent()
    ).replace(/\s+/g, "");
    const config = { secret, algorithm: "sha256", digits: 6, period: 30 };
    await page.locator("#totp").fill(totp(config));
    await page.locator("#userLabel").fill("Captain’s Log local validation");
    await page.locator("#saveTOTPBtn").click();
    await page.getByLabel("Filter query").waitFor();
    privateJSON("totp.json", config);
    enrolled = true;
  } else {
    const config = JSON.parse(
      fs.readFileSync(path.join(privateDir, "totp.json"), "utf8"),
    );
    await page.locator("#otp").fill(totp(config));
    await page.locator("#kc-login").click();
    await page.getByLabel("Filter query").waitFor();
  }
  await context.storageState({
    path: path.join(privateDir, "browser-state.json"),
  });
  fs.chmodSync(path.join(privateDir, "browser-state.json"), 0o600);
  await page.screenshot({
    path: path.join(privateDir, "ui.png"),
    fullPage: true,
  });
  console.log(
    JSON.stringify({
      authenticated: true,
      enrolled,
      path: new URL(page.url()).pathname,
    }),
  );
} finally {
  await browser.close();
}
