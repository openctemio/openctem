import { test, expect, type Page } from '@playwright/test'
import { getE2EConfig } from '../helpers/env'
import { submitSignIn } from '../helpers/auth'

/**
 * Server-side route protection and locale in src/proxy.ts.
 *
 *   1. A signed-out deep link is redirected by the proxy (no page render) to
 *      /login?next=<the page>, and signing in returns to it.
 *   2. A stale session cookie (well-formed, rejected by the API) loads the
 *      page, the client clears the cookies on the 401 and lands on /login
 *      once: no redirect loop.
 *   3. Public pages and the admin console sign-in open without a session; the
 *      admin console redirects to its own sign-in.
 *   4. The CSP nonce still reaches Next.js's scripts, and nothing is blocked.
 *   5. Locale: the cookie wins, Accept-Language is a default, never RTL.
 *
 * Only (1) signs in; the rest needs nothing but a running app.
 */

test.beforeEach(({}, testInfo) => {
  if (!process.env.E2E_BASE_URL && !process.env.E2E_USER_EMAIL) {
    testInfo.skip(true, 'E2E_BASE_URL not set')
  }
})

// Well-formed (three base64url parts) but signed by nobody: the proxy lets it
// through, the API rejects it. Built at runtime so secret scanners do not
// read a literal token.
const FORGED_JWT = [
  Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url'),
  Buffer.from('{"sub":"00000000-0000-0000-0000-000000000000","exp":4102444800}').toString(
    'base64url'
  ),
  Buffer.from('not-a-signature').toString('base64url'),
].join('.')

function cookieUrl(): string {
  return process.env.E2E_BASE_URL ?? 'http://localhost:3000'
}

test('a signed-out deep link goes to /login?next= and comes back after sign-in', async ({
  page,
  request,
}) => {
  const deepLink = '/settings/members?e2e=deep-link'

  // The proxy answers before any page renders.
  const res = await request.get(deepLink, { maxRedirects: 0 })
  expect(res.status()).toBe(307)
  const location = new URL(res.headers()['location'], cookieUrl())
  expect(location.pathname).toBe('/login')
  expect(location.searchParams.get('next')).toBe(deepLink)

  const cfg = getE2EConfig()
  test.skip(!cfg.ok, 'Signing in needs E2E_USER_EMAIL / E2E_USER_PASSWORD / E2E_TENANT_SLUG')
  if (!cfg.ok) return

  await page.goto(deepLink)
  await expect(page).toHaveURL(/\/login\?next=/)
  // Hydrated before typing: a click on the server-rendered form does nothing.
  await page.waitForLoadState('networkidle')
  await page.getByLabel('Email').fill(cfg.config.userEmail)
  await page.getByLabel('Password', { exact: true }).fill(cfg.config.userPassword)
  // The suite's earlier sign-ins can use up the API's per-address limit; the
  // helper waits that out on the 429 instead of timing out.
  await submitSignIn(page, (url) => url.pathname === '/settings/members')
  expect(new URL(page.url()).searchParams.get('e2e')).toBe('deep-link')
})

/**
 * Counts page loads of /login: document requests and client (RSC) navigations,
 * not prefetches.
 */
function countLoginLoads(page: Page): () => number {
  let loads = 0
  page.on('request', (req) => {
    if (req.method() !== 'GET' || new URL(req.url()).pathname !== '/login') return
    const headers = req.headers()
    if (headers['next-router-prefetch'] || headers['purpose'] === 'prefetch') return
    if (req.isNavigationRequest() || headers['rsc']) loads++
  })
  return () => loads
}

test('a stale session cookie lands on /login once, with no loop', async ({ page, context }) => {
  await context.addCookies([
    { name: 'auth_token', value: FORGED_JWT, url: cookieUrl() },
    { name: 'refresh_token', value: FORGED_JWT, url: cookieUrl() },
    {
      name: 'app_tenant',
      value: encodeURIComponent(
        JSON.stringify({
          id: '00000000-0000-0000-0000-000000000001',
          slug: 'stale',
          name: 'Stale',
          role: 'owner',
        })
      ),
      url: cookieUrl(),
    },
  ])
  const loginLoads = countLoginLoads(page)

  // The proxy lets the well-formed cookie through; the API's 401 sends the
  // client to /login.
  await page.goto('/findings')
  await page.waitForURL((url) => url.pathname === '/login', { timeout: 30_000 })
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()

  // It stays there: the stale cookies are gone, so /login shows its form
  // instead of sending the browser back.
  await page.waitForTimeout(5_000)
  expect(new URL(page.url()).pathname).toBe('/login')
  expect(loginLoads()).toBe(1)
  const names = (await context.cookies()).map((c) => c.name)
  expect(names).not.toContain('refresh_token')
  expect(names).not.toContain('auth_token')
  expect(names).not.toContain('app_tenant')
})

test('a malformed session cookie is expired by the proxy itself', async ({ request }) => {
  const res = await request.get('/findings', {
    maxRedirects: 0,
    headers: { cookie: 'refresh_token=garbage; app_tenant=%7B%7D' },
  })
  expect(res.status()).toBe(307)
  expect(new URL(res.headers()['location'], cookieUrl()).pathname).toBe('/login')
  const setCookie = res
    .headersArray()
    .filter((h) => h.name.toLowerCase() === 'set-cookie')
    .map((h) => h.value)
  expect(setCookie.some((c) => /^refresh_token=;/.test(c) && /Max-Age=0/i.test(c))).toBe(true)
  expect(setCookie.some((c) => /^app_tenant=;/.test(c) && /Max-Age=0/i.test(c))).toBe(true)

  // /login itself never redirects on cookies the proxy would reject.
  const login = await request.get('/login?next=%2Ffindings', {
    maxRedirects: 0,
    headers: { cookie: 'refresh_token=garbage; app_tenant=%7B%7D' },
  })
  expect(login.status()).toBe(200)
})

test('public pages open without a session', async ({ request }) => {
  for (const path of [
    '/login',
    '/register',
    '/forgot-password',
    '/reset-password',
    '/set-password',
    '/invitations',
    '/admin/login',
  ]) {
    const res = await request.get(path, { maxRedirects: 0 })
    expect(res.status(), path).toBe(200)
  }
  for (const path of ['/api/health', '/icon']) {
    const res = await request.get(path, { maxRedirects: 0 })
    expect(res.status(), path).not.toBe(307)
  }
})

test('an invitation link from before RFC-041 moves its token into the fragment', async ({
  request,
}) => {
  const res = await request.get('/invitations/this-token-does-not-exist', { maxRedirects: 0 })
  expect(res.status()).toBe(307)
  expect(res.headers()['location']).toMatch(/\/invitations#token=this-token-does-not-exist$/)
})

test('the admin console redirects to its own sign-in', async ({ request }) => {
  const res = await request.get('/admin/organizations', { maxRedirects: 0 })
  expect(res.status()).toBe(307)
  const location = new URL(res.headers()['location'], cookieUrl())
  expect(location.pathname).toBe('/admin/login')
  expect(location.searchParams.get('next')).toBe('/admin/organizations')
})

test('the CSP nonce reaches the page scripts and nothing is blocked', async ({ page, request }) => {
  const res = await request.get('/login')
  const csp = res.headers()['content-security-policy'] ?? ''
  const nonce = /'nonce-([^']+)'/.exec(csp)?.[1]
  expect(nonce, csp).toBeTruthy()
  expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/)
  expect(await res.text()).toContain(`nonce="${nonce}"`)

  await page.addInitScript(() => {
    const w = window as unknown as { __cspViolations: string[] }
    w.__cspViolations = []
    document.addEventListener('securitypolicyviolation', (e) => {
      w.__cspViolations.push(`${e.violatedDirective} ${e.blockedURI}`)
    })
  })
  await page.goto('/login')
  // Hydrated: the form is interactive.
  await page.getByLabel('Email').fill('x@example.test')
  await expect(page.getByLabel('Email')).toHaveValue('x@example.test')
  const violations = await page.evaluate(
    () => (window as unknown as { __cspViolations: string[] }).__cspViolations
  )
  expect(violations).toEqual([])
})

test('locale: cookie first, Accept-Language as a default, never RTL', async ({ request }) => {
  const htmlTag = async (headers: Record<string, string>) => {
    const body = await (await request.get('/login', { headers })).text()
    return /<html[^>]*>/.exec(body)?.[0] ?? ''
  }

  const vi = await htmlTag({ 'accept-language': 'vi-VN,vi;q=0.9,en;q=0.8' })
  expect(vi).toContain('lang="vi"')
  expect(vi).toContain('dir="ltr"')

  const chosen = await htmlTag({ 'accept-language': 'vi-VN,vi;q=0.9', cookie: 'locale=en' })
  expect(chosen).toContain('lang="en"')

  const arabic = await htmlTag({ 'accept-language': 'ar-SA,ar;q=0.9' })
  expect(arabic).toContain('lang="en"')
  expect(arabic).toContain('dir="ltr"')

  // A forged header cannot pick the locale either: the proxy overwrites it.
  const forged = await htmlTag({ 'x-locale': 'ar' })
  expect(forged).toContain('dir="ltr"')
})
