import { chromium, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { privateDir, baseURL } from "./local-auth.mjs";
const browser = await chromium.launch({ headless: true, channel: "chrome" });
const failures = [];
const measurements = [];
async function ready(page, route) {
  if (route.startsWith("/logs/"))
    await expect(page.locator("tbody tr[aria-rowindex]").first()).toBeVisible();
  else if (route.startsWith("/administration/firewalls"))
    await expect(page.locator(".admin-table")).toBeVisible();
  else if (route.startsWith("/administration/storage"))
    await expect(page.locator(".capacity-main")).toBeVisible();
  else if (route.includes("view=configuration"))
    await expect(page.locator(".provider-observation")).toBeVisible();
  else
    await expect(
      page.getByRole("heading", { name: "Connect your identity provider" }),
    ).toBeVisible();
  await expect(page.getByRole("alert")).not.toBeVisible();
}
try {
  const context = await browser.newContext({
    storageState: path.join(privateDir, "browser-state.json"),
    viewport: { width: 1560, height: 1000 },
  });
  const page = await context.newPage();
  page.on("pageerror", (e) => failures.push(e.message));
  page.on("console", (msg) => {
    if (msg.type() === "error")
      failures.push(msg.text().replace(/Bearer\s+\S+/g, "Bearer [redacted]"));
  });
  page.on("request", (r) => {
    const auth = r.headers().authorization;
    if (auth?.startsWith("Bearer ") && new URL(r.url()).origin === baseURL)
      fs.writeFileSync(
        path.join(privateDir, "test-access-token"),
        auth.slice(7),
        { mode: 0o600 },
      );
  });
  await page.goto(
    `${baseURL}/logs/traffic?query=${encodeURIComponent('( device eq "026701001160" )')}`,
  );
  await page.getByLabel("Filter query").waitFor();
  await expect(page.locator(".footer-count")).toContainText("events loaded");
  await page.getByRole("button", { name: "Pause", exact: true }).click();
  await expect(page.getByLabel("Theme")).toBeEnabled();
  await page.getByLabel("Theme").selectOption("dark");
  await expect(page.getByLabel("Theme")).toBeEnabled();
  await page.getByLabel("Density").selectOption("compact");
  await expect(page.getByLabel("Density")).toBeEnabled();
  await expect(page.getByRole("alert")).not.toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  await expect
    .poll(() =>
      page.locator(".stellar-brand img").evaluate((el) => el.naturalWidth),
    )
    .toBeGreaterThan(0);
  await expect
    .poll(() =>
      page.locator(".rail-context > img").evaluate((el) => el.naturalWidth),
    )
    .toBeGreaterThan(0);
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator("tbody tr[aria-rowindex]").first()).toBeVisible();
  const typography = await page.evaluate(() => ({
    ui: getComputedStyle(document.body).fontFamily,
    technical: getComputedStyle(document.querySelector(".ip-value")).fontFamily,
    openSans: document.fonts.check('13px "Open Sans Variable"'),
    firaCode: document.fonts.check('11px "Fira Code Variable"'),
    rowHeight: document
      .querySelector("tbody tr[aria-rowindex]")
      .getBoundingClientRect().height,
    visibleRows: [
      ...document.querySelectorAll("tbody tr[aria-rowindex]"),
    ].filter((e) => {
      const b = e.getBoundingClientRect();
      const sc = document
        .querySelector(".table-scroll")
        .getBoundingClientRect();
      return (
        b.top >=
          document.querySelector("thead").getBoundingClientRect().bottom &&
        b.bottom <= sc.bottom
      );
    }).length,
  }));
  if (
    typography.rowHeight !== 32 ||
    !typography.openSans ||
    !typography.firaCode
  )
    throw new Error("Typography/density failed");
  await page.screenshot({
    path: path.join(privateDir, "ui.png"),
    fullPage: true,
  });
  await page.getByLabel("Density").selectOption("comfortable");
  await expect(page.getByLabel("Density")).toBeEnabled();
  await expect
    .poll(() =>
      page
        .locator("tbody tr[aria-rowindex]")
        .first()
        .evaluate((e) => e.getBoundingClientRect().height),
    )
    .toBe(44);
  await page.getByLabel("Theme").selectOption("light");
  await expect(page.getByLabel("Theme")).toBeEnabled();
  await page.screenshot({
    path: path.join(privateDir, "ui-light-comfortable.png"),
    fullPage: true,
  });
  await page.reload();
  await page.getByLabel("Filter query").waitFor();
  await expect(page.getByLabel("Theme")).toHaveValue("light");
  await expect(page.getByLabel("Density")).toHaveValue("comfortable");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.getByLabel("Density").selectOption("compact");
  await expect(page.getByLabel("Density")).toBeEnabled();
  await ready(page, "/logs/traffic");
  await page.screenshot({
    path: path.join(privateDir, "ui-light.png"),
    fullPage: true,
  });
  for (const theme of ["light", "dark"]) {
    await page.getByLabel("Theme").selectOption(theme);
    await expect(page.getByLabel("Theme")).toBeEnabled();
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      for (const route of [
        "/logs/traffic",
        "/administration/firewalls",
        "/administration/storage",
        "/administration/authentication",
        "/administration/authentication?view=configuration",
      ]) {
        await page.goto(`${baseURL}${route}`);
        await ready(page, route);
        const overflow = await page.evaluate(() => ({
          width: innerWidth,
          document: document.documentElement.scrollWidth,
          body: document.body.scrollWidth,
        }));
        measurements.push({
          theme,
          width,
          route,
          overflow: overflow.document > width || overflow.body > width,
        });
        if (overflow.document > width || overflow.body > width)
          throw new Error(`Page overflow: ${theme} ${width} ${route}`);
        if (width === 390 && route === "/administration/authentication")
          await page.screenshot({
            path: path.join(privateDir, `authentication-${theme}-390.png`),
            fullPage: true,
          });
      }
      if (width === 390) {
        await page
          .getByRole("button", { name: "Open navigation", exact: true })
          .click();
        await expect(
          page.getByRole("navigation", { name: "Log categories" }),
        ).toBeVisible();
        await page.keyboard.press("Escape");
        await expect(
          page.getByRole("button", { name: "Open navigation", exact: true }),
        ).toHaveAttribute("aria-expanded", "false");
      }
    }
  }
  await page.setViewportSize({ width: 1560, height: 1000 });
  await page.goto(`${baseURL}/administration/authentication`);
  await page
    .getByRole("heading", { name: "Connect your identity provider" })
    .waitFor();
  await page.screenshot({
    path: path.join(privateDir, "authentication-dark.png"),
    fullPage: true,
  });
  await page
    .getByRole("button", { name: "Okta SAML 2.0 application integration" })
    .click();
  await expect(
    page.getByRole("heading", { name: "2. Create the Okta application" }),
  ).toBeVisible();
  await expect(
    page.getByText(
      `${baseURL.replace(":18080", ":18089")}/realms/nebulalog/broker/okta/endpoint`,
      { exact: true },
    ),
  ).toBeVisible();
  await page.goto(`${baseURL}/administration/firewalls/026701001160`);
  await page.getByRole("heading", { name: "Observed activity" }).waitFor();
  await page.screenshot({
    path: path.join(privateDir, "firewall-dark.png"),
    fullPage: true,
  });
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Observed activity" }),
  ).toBeVisible();
  if (failures.length)
    throw new Error(
      `Browser errors: ${JSON.stringify([...new Set(failures)])}`,
    );
  fs.writeFileSync(
    path.join(privateDir, "brand-review.json"),
    JSON.stringify({ typography, measurements, errors: failures }, null, 2),
    { mode: 0o600 },
  );
  console.log(
    JSON.stringify({
      typography,
      responsiveCases: measurements.length,
      themeDensityPersistence: true,
      firewallDetailReload: true,
      providerGuideSwitching: true,
      browserErrors: failures,
    }),
  );
} finally {
  await browser.close();
}
