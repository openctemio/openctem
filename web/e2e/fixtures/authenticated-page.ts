import fs from 'fs'
import path from 'path'
import { test as base, expect } from '@playwright/test'
import type { Browser } from '@playwright/test'
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
 * The saved session is signed in again before its access token runs out. The
 * API hands out a 15 minute access token and spends the refresh token the
 * first time it is used. A test that opened after the access token ended
 * renewed it, the saved file kept the spent refresh token, and the first
 * later test that started more than the API's 30 second rotation grace after
 * that renewal was sent to the sign-in page ("the same sign-in was used from
 * two places"). Playwright then restarted the worker, which signed in afresh,
 * and the retry passed: one red test, and a minute and a half of waiting for
 * its page, about every 15 minutes of a shard. A test that starts when the
 * saved session is older than SESSION_MAX_AGE_MS signs in again first.
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
  /** When the saved session was signed in (ms since the epoch). */
  workerSession: { signedInAt: number }
}

/**
 * How old the saved session may be when a test starts: well inside the 15
 * minute access token, with room for the longest test (5 minutes) to finish
 * before it ends.
 */
export const SESSION_MAX_AGE_MS = 8 * 60_000

/** Signs in on a fresh page and saves the session to `file`. */
async function signInAndSave(
  browser: Browser,
  baseURL: string | undefined,
  config: E2EConfig,
  file: string
) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  // loginAs waits out the API's sign-in limit (5 a minute per address)
  // when the login spec and the other workers have used it up.
  const context = await browser.newContext({ baseURL })
  try {
    await loginAs(await context.newPage(), config)
    await context.storageState({ path: file })
  } finally {
    await context.close()
  }
}

export const test = base.extend<Fixtures, WorkerFixtures>({
  workerSession: [
    async ({}, use) => {
      await use({ signedInAt: Date.now() })
    },
    { scope: 'worker' },
  ],

  workerStorageState: [
    async ({ browser, workerSession }, use, workerInfo) => {
      const result = getE2EConfig()
      if (!result.ok) {
        await use('')
        return
      }
      const file = path.resolve(
        workerInfo.project.outputDir,
        `.auth/worker-${workerInfo.parallelIndex}.json`
      )
      await signInAndSave(browser, workerInfo.project.use.baseURL, result.config, file)
      workerSession.signedInAt = Date.now()
      await use(file)
    },
    { scope: 'worker', timeout: 180_000 },
  ],

  // Every test context starts from the worker's signed-in session, signed in
  // again when it is about to outlive its access token.
  storageState: async ({ workerStorageState, workerSession, browser }, use, testInfo) => {
    if (!workerStorageState) return use(undefined)
    if (Date.now() - workerSession.signedInAt > SESSION_MAX_AGE_MS) {
      const result = getE2EConfig()
      if (result.ok) {
        await signInAndSave(
          browser,
          testInfo.project.use.baseURL,
          result.config,
          workerStorageState
        )
        workerSession.signedInAt = Date.now()
      }
    }
    await use(workerStorageState)
  },

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
