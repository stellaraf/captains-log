import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests",
  timeout: 60000,
  workers: 1,
  use: {
    channel: process.env.NEBULALOG_E2E_CHANNEL,
    baseURL: process.env.NEBULALOG_E2E_URL || "http://127.0.0.1:8080",
    storageState: process.env.NEBULALOG_E2E_STORAGE_STATE,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  reporter: "list",
});
