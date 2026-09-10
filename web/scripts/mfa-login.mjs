// A fresh browser session must pass both the password and existing TOTP challenge.
import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";
import { privateDir, passwordLogin, totp } from "./local-auth.mjs";
const browser = await chromium.launch({
  headless: true,
  channel: process.env.NEBULALOG_E2E_CHANNEL || "chrome",
});
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  await passwordLogin(page);
  await page.locator("#otp").waitFor();
  const config = JSON.parse(
    fs.readFileSync(path.join(privateDir, "totp.json"), "utf8"),
  );
  await page.locator("#otp").fill(totp(config));
  await page.locator("#kc-login").click();
  await page.getByLabel("Filter query").waitFor();
  console.log(
    JSON.stringify({
      freshPasswordAndMFALogin: true,
      path: new URL(page.url()).pathname,
    }),
  );
} finally {
  await browser.close();
}
