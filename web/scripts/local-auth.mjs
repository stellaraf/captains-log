// Development verification helpers. Secrets never leave private .local files or the login form.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
export const privateDir = path.resolve("../.local");
export const baseURL =
  process.env.NEBULALOG_E2E_URL || "http://127.0.0.1:18080";
export function privateJSON(name, value) {
  const target = path.join(privateDir, name);
  fs.writeFileSync(target, JSON.stringify(value), { mode: 0o600 });
  fs.chmodSync(target, 0o600);
}
export function totp(config) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of config.secret.toUpperCase().replace(/\s/g, "")) {
    const value = alphabet.indexOf(c);
    if (value < 0) throw new Error("Invalid Base32 enrollment key");
    bits += value.toString(2).padStart(5, "0");
  }
  const key = Buffer.from(
    (bits.match(/.{8}/g) || []).map((b) => parseInt(b, 2)),
  );
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(
    BigInt(Math.floor(Date.now() / (config.period * 1000))),
  );
  const digest = crypto
    .createHmac(config.algorithm, key)
    .update(counter)
    .digest();
  const offset = digest.at(-1) & 15;
  return String(
    (digest.readUInt32BE(offset) & 0x7fffffff) % 10 ** config.digits,
  ).padStart(config.digits, "0");
}
export async function passwordLogin(page) {
  const values = Object.fromEntries(
    fs
      .readFileSync(path.join(privateDir, "dev.env"), "utf8")
      .split("\n")
      .filter((l) => l.includes("=") && !l.startsWith("#"))
      .map((l) => {
        const i = l.indexOf("=");
        return [l.slice(0, i), l.slice(i + 1).replace(/^['"]|['"]$/g, "")];
      }),
  );
  if (!values.NL_ADMIN_PASSWORD)
    throw new Error("Local administrator credentials unavailable");
  await page.goto(`${baseURL}/logs/traffic`);
  await page.locator("#username").fill("administrator");
  await page.locator("#password").fill(values.NL_ADMIN_PASSWORD);
  await page.locator("#kc-login").click();
}
