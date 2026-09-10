import { chromium, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { privateDir, baseURL, totp } from "./local-auth.mjs";
const b = await chromium.launch({ headless: true, channel: "chrome" });
const failures = [];
try {
  const context = await b.newContext({
    viewport: { width: 1440, height: 1000 },
  });
  const p = await context.newPage();
  p.on("pageerror", (e) => failures.push(e.name));
  p.on("request", (r) => {
    const auth = r.headers().authorization;
    if (auth?.startsWith("Bearer ") && new URL(r.url()).origin === baseURL)
      fs.writeFileSync(
        path.join(privateDir, "test-access-token"),
        auth.slice(7),
        { mode: 0o600 },
      );
  });
  await p.goto(`${baseURL}/logs/traffic`);
  await p.locator("#username").waitFor();
  await p.evaluate(() => document.fonts.ready);
  const check = async (label) => {
    const state = await p.evaluate(() => ({
      width: innerWidth,
      scroll: document.documentElement.scrollWidth,
      font: getComputedStyle(document.body).fontFamily,
      logos: [...document.images].map((i) => ({
        loaded: i.complete && i.naturalWidth > 0,
      })),
    }));
    if (state.scroll > state.width) throw new Error(`${label} page overflow`);
    if (state.logos.some((i) => !i.loaded))
      throw new Error(`${label} image failed`);
    return state;
  };
  const desktop = await check("desktop password");
  await p.screenshot({
    path: path.join(privateDir, "login-desktop.png"),
    fullPage: true,
  });
  await p.setViewportSize({ width: 375, height: 900 });
  const mobile = await check("mobile password");
  await p.screenshot({
    path: path.join(privateDir, "login-mobile.png"),
    fullPage: true,
  });
  await p.locator("#username").focus();
  await expect(p.locator("#username")).toBeFocused();
  const env = Object.fromEntries(
    fs
      .readFileSync(path.join(privateDir, "dev.env"), "utf8")
      .split("\n")
      .filter((l) => l.includes("=") && !l.startsWith("#"))
      .map((l) => {
        const i = l.indexOf("=");
        return [l.slice(0, i), l.slice(i + 1).replace(/^['"]|['"]$/g, "")];
      }),
  );
  await p.locator("#username").fill("administrator");
  await p.locator("#password").fill(env.NL_ADMIN_PASSWORD);
  await p.locator("#kc-login").click();
  await p.locator("#otp").waitFor();
  await check("mobile OTP");
  await p.screenshot({
    path: path.join(privateDir, "login-otp-mobile.png"),
    fullPage: true,
    mask: [p.locator("#otp")],
  });
  await p.setViewportSize({ width: 1440, height: 1000 });
  await check("desktop OTP");
  await p.screenshot({
    path: path.join(privateDir, "login-otp-desktop.png"),
    fullPage: true,
    mask: [p.locator("#otp")],
  });
  await p.locator("#otp").fill("000000");
  await p.locator("#kc-login").click();
  await expect(p.getByText("Invalid authenticator code.", {exact:true})).toBeVisible();
  await p.screenshot({
    path: path.join(privateDir, "login-otp-error.png"),
    fullPage: true,
    mask: [p.locator("#otp")],
  });
  const otp = JSON.parse(
    fs.readFileSync(path.join(privateDir, "totp.json"), "utf8"),
  );
  await p.locator("#otp").fill(totp(otp));
  await p.locator("#kc-login").click();
  await p.getByLabel("Filter query").waitFor();
  await context.storageState({
    path: path.join(privateDir, "browser-state.json"),
  });
  fs.chmodSync(path.join(privateDir, "browser-state.json"), 0o600);
  console.log(
    JSON.stringify({
      freshPasswordOTP: true,
      invalidOTPRejected: true,
      desktop,
      mobile,
      errors: failures,
    }),
  );
} finally {
  await b.close();
}
