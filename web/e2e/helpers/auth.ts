import type { Page } from '@playwright/test'
import { expect, test } from '@playwright/test'
import type { E2EConfig } from './env'

/**
 * The API allows 5 sign-ins a minute per client address, counted over a
 * sliding window (api/internal/infra/http/middleware/ratelimit.go); refused
 * attempts do not count. The whole suite signs in from one address: the
 * login spec, every worker's session and the specs that sign in as the
 * limited member already make five sign-ins within seconds, so the next one
 * is answered 429 for up to a minute. The form then shows the API's
 * "Rate limit exceeded" and stays on /login.
 */
export const SIGN_IN_WINDOW_MS = 60_000

/**
 * Clicks "Sign in" on the filled form and waits until the browser reaches a
 * URL `arrived` accepts. When the API refuses with 429 it waits for the
 * refusal toast to go and submits again, until the window has passed, and
 * gives the running test that much more time. Any other outcome (wrong
 * credentials, a redirect elsewhere) still fails after 30 s as before.
 */
export async function submitSignIn(page: Page, arrived: (url: URL) => boolean): Promise<void> {
  const deadline = Date.now() + SIGN_IN_WINDOW_MS + 10_000
  const refused = page.getByText('Rate limit exceeded').first()
  let extended = false
  for (;;) {
    await page.getByRole('button', { name: 'Sign in' }).click()
    const outcome = await Promise.race([
      page
        .waitForURL(arrived, { timeout: 30_000 })
        .then(() => 'arrived' as const)
        .catch(() => 'timeout' as const),
      refused
        .waitFor({ state: 'visible', timeout: 30_000 })
        .then(() => 'rate-limited' as const)
        .catch(() => 'timeout' as const),
    ])
    if (outcome === 'arrived') return
    if (outcome === 'timeout') {
      throw new Error(`sign-in did not reach the expected page within 30s; still at ${page.url()}`)
    }
    if (Date.now() > deadline) {
      throw new Error(`sign-in still answered 429 after the ${SIGN_IN_WINDOW_MS / 1000}s window`)
    }
    console.log(`sign-in: the API's sign-in limit was reached; submitting again once it frees up`)
    if (!extended) {
      extended = true
      try {
        const info = test.info()
        info.setTimeout(info.timeout + SIGN_IN_WINDOW_MS + 30_000)
      } catch {
        // Not inside a test (a worker fixture has its own timeout).
      }
    }
    // The toast lasts a few seconds; a fresh one is the next attempt's answer.
    await refused.waitFor({ state: 'hidden', timeout: 30_000 })
    await page.waitForTimeout(5_000)
  }
}

/**
 * Logs the seed user in via the public login page.
 *
 * Uses the role + label selectors that React Hook Form + shadcn render
 * (FormLabel "Email", FormLabel "Password", submit button "Sign in").
 * Waits for the post-login navigation to land on a tenant route.
 *
 * Returns once the user is on `/{tenantSlug}` (or any path that requires
 * the tenant cookie). Throws if login fails.
 */
export async function loginAs(page: Page, config: E2EConfig): Promise<void> {
  await page.goto('/login')

  // Email + password fields. Targeting by accessible label survives
  // class name and DOM structure changes.
  await page.getByLabel('Email').fill(config.userEmail)
  await page.getByLabel('Password', { exact: true }).fill(config.userPassword)

  await submitSignIn(page, (url) => !url.pathname.startsWith('/login'))

  // After login the user can land on:
  //   - /                          (single-tenant default tenant)
  //   - /select-tenant             (multi-tenant)
  //   - /onboarding/create-team    (no tenant)
  //   - /<tenant-slug>             (when redirectTo carried a tenant URL)
  // For deterministic tests we navigate explicitly to the tenant root.
  if (page.url().includes('/select-tenant')) {
    // Click the configured tenant by its slug or name. The select-tenant
    // page renders cards keyed by tenant slug.
    await page
      .getByRole('link', { name: new RegExp(config.tenantSlug, 'i') })
      .first()
      .click()
    await page.waitForLoadState('networkidle')
  }

  // Sanity check: we should no longer be on /login.
  await expect(page).not.toHaveURL(/\/login(\?|$)/)
}

/**
 * Navigates to a dashboard path. Tenant context is carried by cookies in
 * this app, so dashboard routes are not slug-prefixed. This wrapper exists
 * mostly for symmetry with `loginAs` and to centralise the
 * waitForLoadState call.
 */
export async function gotoDashboardPath(page: Page, pathName: string): Promise<void> {
  const path = pathName.startsWith('/') ? pathName : `/${pathName}`
  await page.goto(path)
  await page.waitForLoadState('networkidle')
}
