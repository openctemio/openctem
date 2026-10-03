import fs from 'fs'
import path from 'path'
import { test as base, expect } from '@playwright/test'
import type { E2EConfig } from '../helpers/env'
import { getE2EConfig } from '../helpers/env'
import { loginAs } from '../helpers/auth'

/**
 * Custom Playwright fixture that yields a `page` already logged in
 * as the seed user. Specs that need an authenticated session simply
 * import `test` from this file instead of `@playwright/test`.
 *
 * Each worker signs in ONCE and every test in that worker reuses the saved
 * session (storageState). Signing in per test hit the API's login rate limit
 * (429) with two workers. One session per worker, rather than one for the
 * whole run, keeps refresh-token rotation within a single process: two
 * workers refreshing the same rotated token would trip reuse detection and
 * revoke the session.
 *
 * The fixture also exposes `e2eConfig` so specs can access the
 * configured tenant slug and credentials without re-reading env vars.
 *
 * If E2E env vars are missing the fixture marks the test as skipped
 * with a clear message — the suite stays green when run from a fresh
 * clone, and only fails when prerequisites are met but assertions break.
 */

type Fixtures = {
  e2eConfig: E2EConfig
}

type WorkerFixtures = {
  /** Path of this worker's saved session, or '' when E2E env is missing. */
  workerStorageState: string
}

export const test = base.extend<Fixtures, WorkerFixtures>({
  workerStorageState: [
    async ({ browser }, use, workerInfo) => {
      const result = getE2EConfig()
      if (!result.ok) {
        await use('')
        return
      }
      const file = path.resolve(
        workerInfo.project.outputDir,
        `.auth/worker-${workerInfo.parallelIndex}.json`
      )
      fs.mkdirSync(path.dirname(file), { recursive: true })
      // loginAs waits out the API's sign-in limit (5 a minute per address)
      // when the login spec and the other workers have used it up.
      const context = await browser.newContext({ baseURL: workerInfo.project.use.baseURL })
      try {
        await loginAs(await context.newPage(), result.config)
        await context.storageState({ path: file })
      } finally {
        await context.close()
      }
      await use(file)
    },
    { scope: 'worker', timeout: 180_000 },
  ],

  // Every test context starts from the worker's signed-in session.
  storageState: ({ workerStorageState }, use) => use(workerStorageState || undefined),

  // Skip the test if env is missing; otherwise return the resolved config.
  e2eConfig: async ({}, use, testInfo) => {
    const result = getE2EConfig()
    if (!result.ok) {
      testInfo.skip(
        true,
        `Skipping E2E test — missing env vars: ${result.missing.join(', ')}.\n` +
          `Copy e2e/.env.example to e2e/.env to enable E2E tests.`
      )
      // testInfo.skip throws, so this line is unreachable, but TS needs it.
      return
    }
    await use(result.config)
  },

  // Resolve e2eConfig first so a missing env skips before the page is used.
  page: async ({ page, e2eConfig }, use) => {
    void e2eConfig
    await use(page)
  },
})

export { expect }
