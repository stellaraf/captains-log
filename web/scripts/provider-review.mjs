import { chromium, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { privateDir, baseURL } from "./local-auth.mjs";
const browser = await chromium.launch({ headless: true, channel: "chrome" });
try {
  const context = await browser.newContext({
    storageState: path.join(privateDir, "browser-state.json"),
    viewport: { width: 1440, height: 1000 },
  });
  const page = await context.newPage();
  let token;
  const failures = [];
  page.on("pageerror", (e) => failures.push(e.name));
  page.on("request", (r) => {
    const auth = r.headers().authorization;
    if (auth?.startsWith("Bearer ") && new URL(r.url()).origin === baseURL) {
      token = auth.slice(7);
      fs.writeFileSync(path.join(privateDir, "test-access-token"), token, {
        mode: 0o600,
      });
    }
  });
  await page.goto(
    `${baseURL}/administration/authentication?provider=okta&view=configuration`,
  );
  await expect(page.locator(".provider-observation")).toBeVisible();
  const initial = await context.request.get(
    `${baseURL}/api/identity/providers/okta`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (!initial.ok() || (await initial.json()).provider.configured)
    throw new Error(
      "Okta alias is already configured or unavailable; no mutation performed",
    );
  for (const [role, name] of [
    ["Viewer", "NebulaLog-Viewers"],
    ["Analyst", "NebulaLog-Analysts"],
    ["Administrator", "NebulaLog-Administrators"],
  ])
    await page.getByLabel(`${role} group name`, { exact: true }).fill(name);
  await expect(
    page.getByRole("checkbox", { name: "Enable this provider after saving" }),
  ).not.toBeChecked();
  await page.getByLabel("Metadata XML", { exact: true }).fill("<invalid>");
  const invalid = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/api/identity/providers/okta/preview",
  );
  await page
    .getByRole("button", { name: "Review configuration", exact: true })
    .click();
  if ((await invalid).status() !== 400)
    throw new Error("Invalid metadata was not rejected");
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await page
    .getByLabel("Upload metadata XML", { exact: true })
    .setInputFiles(path.join(privateDir, "saml-ui-fixture.xml"));
  const previewResponse = page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname === "/api/identity/providers/okta/preview" &&
      r.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Review configuration", exact: true })
    .click();
  const preview = (await (await previewResponse).json()).preview;
  if (
    preview.alias !== "okta" ||
    preview.enabled ||
    preview.external_login_tested ||
    !preview.certificates?.length
  )
    throw new Error("Unexpected preview boundary");
  await expect(
    page.getByRole("dialog", { name: "Review Okta configuration" }),
  ).toBeVisible();
  await expect(
    page.getByRole("dialog").getByText(preview.entity_id, { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("dialog").getByText(preview.sso_url, { exact: true }),
  ).toBeVisible();
  const saveResponse = page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname === "/api/identity/providers/okta" &&
      r.request().method() === "PUT",
  );
  await page
    .getByRole("button", { name: "Save disabled provider", exact: true })
    .click();
  const saved = (await (await saveResponse).json()).provider;
  if (
    !saved?.configured ||
    !saved.managed ||
    saved.enabled ||
    saved.external_login_tested
  )
    throw new Error("Provider was not saved disabled");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(
    page.getByText("Provider configuration saved with sign-in disabled.", {
      exact: false,
    }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page
      .locator(".provider-observation")
      .getByText("Saved · disabled", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByLabel("Viewer group name", { exact: true }),
  ).toHaveValue("NebulaLog-Viewers");
  const checkResponse = page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname === "/api/identity/providers/okta/test" &&
      r.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Check configuration", exact: true })
    .click();
  const check = (await (await checkResponse).json()).status;
  if (!check.configuration_valid || check.external_login_tested)
    throw new Error("Configuration-only check failed");
  await expect(
    page.getByText("Configuration checks passed", { exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: path.join(privateDir, "provider-configuration.png"),
    fullPage: true,
  });
  const final = await context.request.get(
    `${baseURL}/api/identity/providers/okta`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  const state = (await final.json()).provider;
  if (!state.configured || state.enabled)
    throw new Error("Provider did not remain disabled");
  console.log(
    JSON.stringify({
      invalidXMLRejected: true,
      reviewIssuerEndpointCertificates: true,
      savedDisabled: true,
      persistedGroups: true,
      configurationOnlyCheck: true,
      externalLoginTested: false,
      fixtureAlias: "okta",
      fixtureRetainedDisabled: true,
      browserErrors: failures,
    }),
  );
} finally {
  await browser.close();
}
