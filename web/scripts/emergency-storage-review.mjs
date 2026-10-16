// Isolated UI contract checks. This fixture never authenticates to a real app,
// changes a policy, or deletes data. It is not native appliance acceptance.
import { chromium, expect } from "@playwright/test";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = path.resolve(process.env.EMERGENCY_REVIEW_OUTPUT || path.join(root, "../.local/emergency-storage-review"));
await fs.mkdir(out, { recursive: true, mode: 0o700 });
const apiFixture = `
const listeners = new Set();
const names=['traffic','threat','url','wildfire','dns','data','hip','globalprotect','iptag','userid','decryption','tunnel','configuration','system','authentication'];
const value={policy:{revision:4,enabled:true,trigger_percent:95,recover_percent:90,
 minimum_days:Object.fromEntries(names.map(name=>[name,name==='traffic'?1:name==='url'?7:30]))},
 status:{state:'normal',observed_at:new Date().toISOString(),message:'Log disk is below the cleanup threshold.',used_percent:42},
 recent_actions:[{id:'synthetic-review-action',state:'complete',created_at:new Date().toISOString(),updated_at:new Date().toISOString(),policy_revision:3,table_uuid:'synthetic-table',partition_id:'synthetic-partition',log_type:'traffic',partition_day:'2026-09-01',rows:123456,bytes_on_disk:98765432,message:'Synthetic completed action for UI rendering only.'}]};
const state=window.__emergencyReview={value,user:{id:'synthetic-review-user',name:'Review',role:new URLSearchParams(location.search).get('role')||'ADMINISTRATOR'},requests:[],mode:'ok',session:0,changeSession(){this.session++;for(const listener of listeners)listener();}};
export const authSessionSnapshot=()=>state.session;
export const subscribeAuthSession=listener=>{listeners.add(listener);return()=>listeners.delete(listener);};
export const json=(method,value)=>({method,body:JSON.stringify(value)});
export async function api(url,options={}) {
 if(!['/api/storage/emergency','/api/me'].includes(url))throw Error('Unexpected fixture endpoint');
 if(options.expectedSession!==undefined&&options.expectedSession!==state.session)throw Error('Session changed');
 const request={url,method:options.method||'GET',body:options.body?JSON.parse(options.body):null,completed:false};
 state.requests.push(request);
 try {
 const mode=state.mode;
 await new Promise(resolve=>setTimeout(resolve,mode==='late_save'&&options.method==='PUT'?400:20));
 if(mode==='unavailable')throw Error('Controller database unavailable.');
 if(mode==='expired'){state.changeSession();throw Error('Your session has expired.');}
 if(url==='/api/me')return structuredClone(state.user);
 if(options.method==='PUT') {
  if(mode==='conflict')throw Error('Policy revision changed.');
  const {expected_revision,...policy}=JSON.parse(options.body);
  if(expected_revision!==state.value.policy.revision)throw Error('Policy revision changed.');
  state.value.policy={...policy,revision:expected_revision+1};
 }
 return structuredClone(state.value);
 } finally {request.completed=true;}
}
`;
const fixturePlugin = {
  name: "isolated-emergency-review",
  enforce: "pre",
  resolveId(id, importer) {
    if (id === "/__emergency-entry.tsx") return "\0emergency-entry.tsx";
    if (id === "./api" && importer?.endsWith("/src/EmergencyStorage.tsx")) return "\0emergency-fixture-api";
  },
  load(id) {
    if (id === "\0emergency-fixture-api") return apiFixture;
    if (id === "\0emergency-entry.tsx") return `
      import React from 'react'; import {createRoot} from 'react-dom/client';
      import {EmergencyStorage} from '/src/EmergencyStorage.tsx';
      import '/src/style.css';
      import '@fontsource-variable/open-sans'; import '@fontsource-variable/fira-code';
      const role=new URLSearchParams(location.search).get('role')||'ADMINISTRATOR';
      createRoot(document.getElementById('root')).render(React.createElement('main',{style:{padding:24,maxWidth:1200,margin:'auto'}},
        React.createElement('p',null,'ISOLATED UI REVIEW · synthetic policy and history'),
        React.createElement(EmergencyStorage,{user:{id:'synthetic-review-user',name:'Review',role}})));`;
  },
  configureServer(server) {
    server.middlewares.use(async (req, res, next) => {
      if (!req.url?.startsWith("/__emergency-review")) return next();
      const html = await server.transformIndexHtml(req.url, '<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Isolated emergency storage review</title></head><body><div id="root"></div><script type="module" src="/__emergency-entry.tsx"></script></body></html>');
      res.setHeader("Content-Type", "text/html"); res.end(html);
    });
  },
};
const server = await createServer({ root, configFile: false, cacheDir: path.join(out, "vite"),
  plugins: [fixturePlugin, react({ include: /\/src\/.*\.[jt]sx?$/ })], server: { host: "127.0.0.1", port: 0 }, logLevel: "error" });
let browser;
const checks = [];
try {
  await server.listen();
  const port = server.httpServer.address().port;
  browser = await chromium.launch({ channel: process.env.NEBULALOG_E2E_CHANNEL || "chrome", headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 1100 } });
  const errors = [];
  page.on("pageerror", error => { errors.push(error.message); console.error("Isolated browser error:", error.message); });
  const url = `http://127.0.0.1:${port}/__emergency-review`;
  await page.goto(url);
  const save = page.getByRole("button", { name: "Save emergency policy", exact: true });
  const ack = page.getByLabel("I understand this policy can permanently delete");
  await expect(save).toBeDisabled();
  await page.getByLabel("Traffic emergency minimum days", { exact: true }).fill("2");
  await expect(save).toBeDisabled();
  await ack.check();
  await expect(save).toBeEnabled();
  await page.getByLabel("Emergency cleanup stop percentage").fill("89");
  await expect(ack).not.toBeChecked();
  await expect(save).toBeDisabled();
  await ack.check(); await save.click();
  await expect(page.getByText("Emergency policy revision 5 saved.", { exact: false })).toBeVisible();
  const put = await page.evaluate(() => window.__emergencyReview.requests.find(request => request.method === "PUT"));
  expect(put.body.expected_revision).toBe(4);
  expect(put.body.minimum_days.traffic).toBe(2);
  expect(put.body.recover_percent).toBe(89);
  expect(await page.evaluate(() => window.__emergencyReview.requests.filter(request => request.method === "PUT").length)).toBe(1);
  await expect(ack).not.toBeChecked();
  checks.push("Confirmation binds to the latest edited values; expected revision and policy are submitted once.");

  await page.getByLabel("Emergency cleanup start percentage").fill("94"); await ack.check();
  await page.evaluate(() => { window.__emergencyReview.mode = "conflict"; });
  await save.click();
  await expect(page.getByRole("alert")).toContainText("Policy revision changed");
  await expect(save).toHaveCount(0);
  await page.evaluate(() => { window.__emergencyReview.mode = "ok"; });
  await page.getByRole("button", { name: "Refresh emergency storage protection" }).click();
  await expect(page.getByLabel("Emergency cleanup start percentage")).toHaveValue("95");
  checks.push("Revision conflict clears the editable snapshot until an explicit successful refresh.");

  await page.evaluate(() => { window.__emergencyReview.mode = "unavailable"; });
  await page.getByRole("button", { name: "Refresh emergency storage protection" }).click();
  await expect(page.getByRole("alert")).toContainText("Controller database unavailable");
  await expect(save).toHaveCount(0);
  await expect(page.getByText("42.0% used on the log disk")).toHaveCount(0);
  checks.push("Failed refresh removes previous operational claims and write controls.");

  await page.goto(url + "?role=VIEWER");
  await expect(page.getByLabel("Enable automatic emergency cleanup")).toBeDisabled();
  await expect(save).toHaveCount(0);
  await expect(page.getByText("An administrator can change this policy.")).toBeVisible();
  checks.push("Viewer sees policy/history but cannot change values or submit a policy.");

  await page.goto(url);
  await page.getByLabel("Traffic emergency minimum days", { exact: true }).fill("3"); await ack.check();
  await page.evaluate(() => { window.__emergencyReview.mode = "late_save"; });
  await save.click();
  await page.evaluate(() => { window.__emergencyReview.mode = "ok"; window.__emergencyReview.changeSession(); });
  await expect.poll(() => page.evaluate(() => window.__emergencyReview.requests.filter(request => request.method === "PUT").every(request => request.completed))).toBe(true);
  await expect(page.getByText("Emergency policy revision 5 saved.", { exact: false })).toHaveCount(0);
  await expect(save).toHaveCount(0);
  await expect(page.getByRole("alert")).toContainText("sign-in session changed");
  checks.push("Late save response from an earlier session does not display success or restore its draft.");

  await page.goto(url);
  await expect(save).toBeVisible();
  const beforeExpiry = await page.evaluate(() => window.__emergencyReview.requests.length);
  await page.evaluate(() => { window.__emergencyReview.mode = "expired"; });
  await page.getByRole("button", { name: "Refresh emergency storage protection" }).click();
  await expect(page.getByRole("alert")).toContainText("sign-in session changed");
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => window.__emergencyReview.requests.length)).toBe(beforeExpiry + 2);
  checks.push("Authentication expiry clears controls without an automatic request/invalidation loop.");

  await page.goto(url);
  await expect(save).toBeVisible();
  await page.evaluate(() => { window.__emergencyReview.user.role = "VIEWER"; window.__emergencyReview.changeSession(); });
  await expect(save).toHaveCount(0);
  await page.getByRole("button", { name: "Refresh emergency storage protection" }).click();
  await expect(page.getByLabel("Enable automatic emergency cleanup")).toBeDisabled();
  await expect(save).toHaveCount(0);
  await expect(page.getByText("An administrator can change this policy.")).toBeVisible();
  checks.push("Administrator role loss remains read-only after explicit refresh of the same page.");

  await page.goto(url);
  await expect(save).toBeVisible();
  await page.screenshot({ path: path.join(out, "desktop-light.png"), fullPage: true });
  await page.evaluate(() => { document.documentElement.dataset.theme = "dark"; });
  await page.screenshot({ path: path.join(out, "desktop-dark.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(out, "mobile-dark.png"), fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(errors).toEqual([]);
  checks.push("Desktop light/dark and mobile render without page overflow or browser errors.");
  const receipt = { at: new Date().toISOString(), passed: true, synthetic_ui_only: true, live_api_verified: false, checks, screenshots: ["desktop-light.png", "desktop-dark.png", "mobile-dark.png"] };
  await fs.writeFile(path.join(out, "receipt.json"), JSON.stringify(receipt, null, 2) + "\n", { mode: 0o600 });
  console.log(JSON.stringify({ passed: true, checks: checks.length, receipt: path.join(out, "receipt.json") }));
} finally { await browser?.close(); await server.close(); }
