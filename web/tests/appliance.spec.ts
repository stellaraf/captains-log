import { test, expect } from "@playwright/test";
// Run only against real services. A Keycloak-enrolled session is required for authenticated cases.
test("requires authentication before exposing logs", async ({ browser }) => {
  const context = await browser.newContext({
    storageState: { cookies: [], origins: [] },
  });
  const page = await context.newPage();
  await page.goto(
    (process.env.NEBULALOG_E2E_URL || "http://127.0.0.1:8080") +
      "/logs/traffic",
  );
  await expect(page.locator("#username")).toBeVisible({ timeout: 20000 });
  await expect(page.getByLabel("Filter query")).not.toBeVisible();
  await context.close();
});
test("real saved filter persists and can be loaded and deleted", async ({
  page,
}) => {
  test.skip(
    !process.env.NEBULALOG_E2E_STORAGE_STATE,
    "Requires a real enrolled Keycloak session; no authentication bypass.",
  );
  const name = `E2E persistence ${Date.now()}`;
  await page.goto("/logs/traffic");
  await expect(page.getByLabel("Filter query")).toBeVisible();
  await page.getByLabel("Filter query").fill("( port.dst eq 443 )");
  await page.getByRole("button", { name: "Apply", exact: true }).click();
  await expect(page.getByText("Filter applied", { exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).not.toBeVisible();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByLabel("Name", { exact: true }).fill(name);
  await page
    .getByLabel("Description", { exact: true })
    .fill("Temporary browser verification; removed at end of test.");
  await page.getByRole("button", { name: "Save filter", exact: true }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await page.reload();
  await expect(page.getByLabel("Filter query")).toBeVisible();
  await page.getByRole("button", { name: "Load", exact: true }).click();
  await page.getByLabel("Find saved filters").fill(name);
  const article = page
    .getByRole("article")
    .filter({ has: page.getByRole("heading", { name, exact: true }) });
  await expect(article).toBeVisible();
  await article.getByRole("button", { name: "Load", exact: true }).click();
  await expect(page.getByLabel("Filter query")).toHaveValue(
    "( port.dst eq 443 )",
  );
  await page.getByRole("button", { name: "Load", exact: true }).click();
  await page.getByLabel("Find saved filters").fill(name);
  await article
    .getByRole("button", { name: `Delete ${name}`, exact: true })
    .click();
  await page
    .getByRole("button", { name: "Delete filter", exact: true })
    .click();
  await expect(article).not.toBeVisible();
});
test("graphical filters share parser validation and layouts persist", async ({
  page,
}) => {
  test.skip(
    !process.env.NEBULALOG_E2E_STORAGE_STATE,
    "Requires real MFA session.",
  );
  await page.goto("/logs/traffic");
  await expect(page.getByLabel("Filter query")).toBeVisible();
  await page.getByRole("button", { name: "Add filter", exact: true }).click();
  await page.getByLabel("Attribute", { exact: true }).selectOption("addr.src");
  await page.getByLabel("Operator", { exact: true }).selectOption("in");
  await page.getByLabel("Value", { exact: true }).fill("10.0.0.0/8");
  await page
    .getByRole("button", { name: "Add & apply filter", exact: true })
    .click();
  await expect(page.getByLabel("Filter query")).toHaveValue(
    '( addr.src in "10.0.0.0/8" )',
  );
  await page.getByRole("button", { name: "Columns", exact: true }).click();
  const serial = page.getByRole("checkbox", { name: "Serial", exact: true });
  const original = await serial.isChecked();
  await serial.setChecked(!original);
  await page.getByRole("button", { name: "Save layout", exact: true }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await page.reload();
  await expect(page.getByLabel("Filter query")).toBeVisible();
  await page.getByRole("button", { name: "Columns", exact: true }).click();
  await expect(serial).toBeChecked({ checked: !original });
  await serial.setChecked(original);
  await page.getByRole("button", { name: "Save layout", exact: true }).click();
  await page.getByRole("button", { name: "Pause", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Resume", exact: true }),
  ).toBeVisible();
});
test("live diagnostics and storage render observed state", async ({ page }) => {
  test.skip(
    !process.env.NEBULALOG_E2E_STORAGE_STATE,
    "Requires real MFA session.",
  );
  await page.goto("/administration/diagnostics");
  await expect(
    page.getByRole("heading", { name: "Syslog receiver" }),
  ).toBeVisible();
  await expect(
    page.getByText("Messages received", { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("alert")).not.toBeVisible();
  await page
    .getByRole("link", { name: "Storage & retention", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Data storage" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Retention policy" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Host storage integration" }),
  ).toBeVisible();
  await expect(page.getByRole("alert")).not.toBeVisible();
  await page
    .getByRole("link", { name: "Security & compliance", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Security posture" }),
  ).toBeVisible();
  await expect(page.getByRole("alert")).not.toBeVisible();
});
