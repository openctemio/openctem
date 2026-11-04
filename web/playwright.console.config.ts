import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright configuration for the platform console (web/console).
 *
 * The console is its own Next.js app on its own site, so it has its own
 * config, specs (console/e2e/specs) and workflow (.github/workflows/
 * console-e2e.yml). The tenant app's suite (playwright.config.ts) never sees
 * these specs. Page checks come from web/e2e/helpers, shared with that suite.
 *
 * Local run: console/e2e/README.md. Environment:
 *   CONSOLE_E2E_BASE_URL     the console site (default http://127.0.0.1:3001)
 *   CONSOLE_E2E_EMAIL        the platform administrator's sign-in email
 *   CONSOLE_E2E_PASSWORD     its password (already changed from the temporary one)
 *   CONSOLE_E2E_TOTP_SECRET  its authenticator secret (base32)
 * Without them the suite fails at setup: it never guesses credentials.
 */
const baseURL = process.env.CONSOLE_E2E_BASE_URL ?? 'http://127.0.0.1:3001'
const isCI = !!process.env.CI

export default defineConfig({
  testDir: './console/e2e/specs',
  testMatch: '**/*.spec.ts',
  outputDir: './test-results-console',
  globalSetup: './console/e2e/global-setup.ts',
  timeout: 90_000,
  expect: { timeout: 10_000 },
  // One console session, one API sign-in limit: no parallel workers.
  workers: 1,
  fullyParallel: false,
  forbidOnly: isCI,
  retries: isCI ? 1 : 0,
  reporter: isCI ? [['list'], ['github']] : [['list']],
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    locale: 'en-US',
    actionTimeout: 15_000,
    navigationTimeout: 45_000,
    storageState: './.console-e2e-auth/admin.json',
  },
  projects: [{ name: 'console', use: { ...devices['Desktop Chrome'] } }],
})
