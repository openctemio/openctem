import { defineConfig, devices } from '@playwright/test'

/**
 * Design gate (docs/development/design-gate.md): the pages listed in
 * e2e/design/manifest.ts, compared with the images exported from their design
 * boards, plus a layout pass in Vietnamese with long and empty data.
 *
 * Self-contained: no API, database or seed. A mock API on 127.0.0.1 answers
 * from e2e/design/fixtures (the design's sample dataset) and is the web
 * server's backend; the browser reaches nothing but the web server.
 *
 *   npx playwright test -c playwright.design.config.ts
 *
 * Ports: DESIGN_WEB_PORT (default 3100), DESIGN_MOCK_PORT (default 3199).
 * A web server already listening on the web port is reused (local runs);
 * otherwise `next dev` is started with the mock API as its backend.
 */

const webPort = process.env.DESIGN_WEB_PORT ?? '3100'
const mockPort = process.env.DESIGN_MOCK_PORT ?? '3199'
process.env.DESIGN_MOCK_PORT = mockPort
const baseURL = `http://127.0.0.1:${webPort}`

export default defineConfig({
  testDir: './e2e/design',
  testMatch: '**/*.design.ts',
  outputDir: 'test-results-design/results',
  globalSetup: './e2e/design/global-setup.ts',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  // One mock API holds the current fixture set: run the tests one at a time.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI
    ? [
        ['list'],
        ['github'],
        ['html', { open: 'never', outputFolder: 'test-results-design/report' }],
      ]
    : [['list'], ['html', { open: 'never', outputFolder: 'test-results-design/report' }]],
  use: {
    ...devices['Desktop Chrome'],
    baseURL,
    locale: 'en-US',
    timezoneId: 'UTC',
    deviceScaleFactor: 1,
    navigationTimeout: 60_000,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'design', use: { browserName: 'chromium' } }],
  webServer: {
    command: `npx next dev --port ${webPort} --hostname 127.0.0.1`,
    url: `${baseURL}/login`,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
    env: {
      BACKEND_API_URL: `http://127.0.0.1:${mockPort}`,
      NEXT_PUBLIC_APP_URL: baseURL,
      NEXT_TELEMETRY_DISABLED: '1',
      SECURE_COOKIES: 'false',
    },
  },
})
