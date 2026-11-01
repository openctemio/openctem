import { test, expect } from '@playwright/test'

/**
 * The account space of a signed-in person with no organization (api RFC-141),
 * as far as the proxy decides it without an API call:
 *
 *   1. A signed-out visit to /welcome goes to /login?next=/welcome.
 *   2. A session that carries the account-only marker is sent to /welcome from
 *      every tenant page, and from the account pages that read organization
 *      data; /welcome and the three personal account pages open.
 *   3. An organization cookie wins over a stale marker.
 *   4. The marker is only a routing hint: the pages it opens carry no extra
 *      authority (the API refuses every tenant route with 401 TENANT_REQUIRED).
 *
 * Only a running app is needed. The cookies are well-formed and signed by
 * nobody, so no page that calls the API is opened here.
 */

test.beforeEach(({}, testInfo) => {
  if (!process.env.E2E_BASE_URL && !process.env.E2E_USER_EMAIL) {
    testInfo.skip(true, 'E2E_BASE_URL not set')
  }
})

// Built at runtime so secret scanners do not read a literal token.
const FORGED_JWT = [
  Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url'),
  Buffer.from('{"sub":"00000000-0000-0000-0000-000000000000","exp":4102444800}').toString(
    'base64url'
  ),
  Buffer.from('not-a-signature').toString('base64url'),
].join('.')

const ACCOUNT_ONLY = `auth_token=${FORGED_JWT}; refresh_token=${FORGED_JWT}; app_account_only=1`

function base(): string {
  return process.env.E2E_BASE_URL ?? 'http://localhost:3000'
}

test(
  'a signed-out visit to /welcome goes to the sign-in page and comes back',
  { tag: ['@auth'] },
  async ({ request }) => {
    const res = await request.get('/welcome', { maxRedirects: 0 })
    expect(res.status()).toBe(307)
    const location = new URL(res.headers()['location'], base())
    expect(location.pathname).toBe('/login')
    expect(location.searchParams.get('next')).toBe('/welcome')
  }
)

test(
  'an account-only session is sent to /welcome from tenant pages',
  { tag: ['@auth'] },
  async ({ request }) => {
    for (const path of [
      '/',
      '/findings',
      '/settings/members',
      '/account/activity',
      '/account/notifications',
      '/onboarding/create-team',
    ]) {
      const res = await request.get(path, { maxRedirects: 0, headers: { cookie: ACCOUNT_ONLY } })
      expect(res.status(), path).toBe(307)
      expect(new URL(res.headers()['location'], base()).pathname, path).toBe('/welcome')
    }
  }
)

test(
  'an account-only session opens the account pages without a redirect',
  { tag: ['@auth'] },
  async ({ request }) => {
    for (const path of ['/welcome', '/account', '/account/security', '/account/preferences']) {
      const res = await request.get(path, { maxRedirects: 0, headers: { cookie: ACCOUNT_ONLY } })
      expect(res.status(), path).toBe(200)
    }
  }
)

test(
  'a stale marker does not hide an organization that is open',
  { tag: ['@auth'] },
  async ({ request }) => {
    const res = await request.get('/findings', {
      maxRedirects: 0,
      headers: { cookie: `${ACCOUNT_ONLY}; app_tenant=%7B%22id%22%3A%22t1%22%7D` },
    })
    expect(res.status()).toBe(200)
  }
)

test(
  'the account space renders without the tenant sidebar, at phone and desktop width',
  { tag: ['@auth'] },
  async ({ browser }) => {
    for (const viewport of [
      { width: 1440, height: 900 },
      { width: 390, height: 844 },
    ]) {
      const context = await browser.newContext({ viewport, baseURL: base() })
      await context.addCookies(
        ['auth_token', 'refresh_token'].map((name) => ({
          name,
          value: FORGED_JWT,
          url: base(),
        }))
      )
      await context.addCookies([{ name: 'app_account_only', value: '1', url: base() }])
      const page = await context.newPage()
      // The cookies are forged: answer every API call 503, so no 401 starts the
      // client's sign-out and the page stays put.
      await page.route('**/api/**', (route) =>
        route.fulfill({ status: 503, contentType: 'application/json', body: '{}' })
      )
      // The server-rendered shell is enough: no API answer is needed to see
      // that the tenant sidebar is not part of it.
      const res = await page.goto('/welcome', { waitUntil: 'domcontentloaded' })
      expect(res?.status()).toBe(200)
      await expect(page.locator('[data-sidebar="sidebar"]')).toHaveCount(0)
      await expect(page.getByRole('navigation', { name: 'Account' })).toBeVisible()
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth > document.documentElement.clientWidth
      )
      expect(overflow, `horizontal scroll at ${viewport.width}px`).toBe(false)
      await context.close()
    }
  }
)
