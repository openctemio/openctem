import { createHmac } from 'node:crypto'
import { test, expect, type Page } from '@playwright/test'
import { submitSignIn } from '../helpers/auth'

/**
 * A first sign-in never ends in an unexplained sign-out.
 *
 * Regression this guards: a person signing in with Google for the first time
 * (no account before) was sent back to /login. The callback landed them on
 * the dashboard with a token that has no organization; its first
 * organization request answered 401 TENANT_REQUIRED, the refresh had no
 * organization to renew and failed, and the client signed them out. An
 * invited person whose organization requires two-factor authentication was
 * stuck the same way: the organization refused the Google session, the
 * account token was refused because they now had an organization, and the
 * setup could not start from a Google session.
 *
 * Needs the stack with the Google stand-in (e2e/ci/fake-google.compose.yml)
 * and the seed run with E2E_FAKE_GOOGLE=1; skipped without them. The browser
 * side of the provider is answered here: the "authorization" redirects back
 * with a code naming the identity, which the stand-in turns into a signed
 * id_token. No request leaves the stack.
 */

const env = process.env
const enabled = !!env.E2E_FAKE_GOOGLE

test.describe('first sign-in', { tag: ['@auth'] }, () => {
  test.skip(!enabled, 'needs the Google stand-in (E2E_FAKE_GOOGLE)')
  // The member case signs in with the account the invitation case created.
  test.describe.configure({ mode: 'serial' })

  /** Answers the provider's authorization page for `email` (stable subject per address). */
  async function googleAs(page: Page, email: string) {
    await page.route('https://accounts.google.com/**', async (route) => {
      const url = new URL(route.request().url())
      // A Workspace account: the provider vouches for the address (hd), so an
      // invitation to it counts on a closed installation.
      const identity = {
        sub: `sub-${email}`,
        email,
        name: email.split('@')[0],
        hd: email.split('@')[1],
      }
      const code = Buffer.from(JSON.stringify(identity)).toString('base64url')
      const back = new URL(url.searchParams.get('redirect_uri')!)
      back.searchParams.set('code', code)
      back.searchParams.set('state', url.searchParams.get('state')!)
      await route.fulfill({ status: 302, headers: { location: back.toString() } })
    })
  }

  /** Signs in with Google and records every sign-out the web asks the API for. */
  async function signInWithGoogle(page: Page, email: string) {
    await googleAs(page, email)
    const logouts: string[] = []
    page.on('request', (r) => {
      if (r.url().includes('/auth/logout')) logouts.push(r.url())
    })
    await page.goto('/login')
    await page.getByRole('button', { name: 'Google' }).click()
    await page.waitForURL((u) => !u.pathname.startsWith('/auth/'), { timeout: 30_000 })
    return logouts
  }

  /** RFC 6238 code (SHA-1, 30 s, 6 digits) for a base32 secret. */
  function totp(secret: string): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    let bits = ''
    for (const c of secret.replace(/[\s=]/g, '').toUpperCase()) {
      bits += alphabet.indexOf(c).toString(2).padStart(5, '0')
    }
    const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)))
    const counter = Buffer.alloc(8)
    counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
    const h = createHmac('sha1', key).update(counter).digest()
    const o = h[h.length - 1] & 0xf
    const n = (h.readUInt32BE(o) & 0x7fffffff) % 1_000_000
    return n.toString().padStart(6, '0')
  }

  /** Completes the enrollment step on the page (manual key, code, recovery codes). */
  async function enrollTotp(page: Page) {
    const key = page
      .locator('code')
      .filter({ hasText: /^[A-Z2-7 ]{16,}$/ })
      .first()
    await expect(key).toBeVisible({ timeout: 30_000 })
    const secret = (await key.textContent())!.replace(/\s/g, '')
    // A full code submits itself.
    await page.getByLabel('Authentication code').fill(totp(secret))
    await page.getByLabel('I have saved my recovery codes').check({ timeout: 30_000 })
    await page.getByRole('button', { name: 'Continue' }).click()
  }

  async function sessionOrgSlug(page: Page): Promise<string | null> {
    const cookie = (await page.context().cookies()).find((c) => c.name === 'app_tenant')
    if (!cookie) return null
    try {
      return (JSON.parse(decodeURIComponent(cookie.value)) as { slug?: string }).slug ?? null
    } catch {
      return null
    }
  }

  test('closed sign-up, no invitation: a clear page, never a loop back to /login', async ({
    page,
  }) => {
    const logouts = await signInWithGoogle(page, env.E2E_SOCIAL_NEW_EMAIL!)
    await expect(page).toHaveURL(/\/not-set-up/)
    await expect(page.getByText("Your organization isn't set up yet")).toBeVisible()
    expect(logouts).toEqual([])
  })

  test('closed sign-up with an invitation: the account space offers it, Join opens the organization', async ({
    page,
  }) => {
    const logouts = await signInWithGoogle(page, env.E2E_SOCIAL_INVITED_EMAIL!)
    await expect(page).toHaveURL(/\/welcome/)
    await expect(page.getByText(env.E2E_INVITE_ORG!)).toBeVisible({ timeout: 30_000 })
    // Account settings work without an organization.
    await page.goto('/account/security')
    await expect(page).toHaveURL(/\/account\/security/)
    await page.goto('/welcome')
    await page.getByRole('button', { name: 'Join' }).first().click()
    await page.waitForURL((u) => u.pathname === '/', { timeout: 30_000 })
    expect(await sessionOrgSlug(page)).toBe(env.E2E_INVITE_ORG_SLUG)
    expect(logouts).toEqual([])
  })

  test('an existing member signs in with Google straight into the organization', async ({
    page,
  }) => {
    // The account the previous case created and joined.
    const logouts = await signInWithGoogle(page, env.E2E_SOCIAL_INVITED_EMAIL!)
    await page.waitForURL((u) => u.pathname === '/', { timeout: 30_000 })
    expect(await sessionOrgSlug(page)).toBe(env.E2E_INVITE_ORG_SLUG)
    expect(logouts).toEqual([])
  })

  test('invited into an organization that requires 2FA: account settings work, enroll, then the organization', async ({
    page,
  }) => {
    const logouts = await signInWithGoogle(page, env.E2E_SOCIAL_MFA_EMAIL!)
    await expect(page).toHaveURL(/\/welcome/)
    await page.getByRole('button', { name: 'Join' }).first().click()
    // Joined; the organization asks for two-factor authentication first.
    await page.waitForURL(/\/two-factor-setup/, { timeout: 30_000 })
    // The person may look at their account settings first: no sign-out.
    await page.goto('/account/security')
    await expect(page).toHaveURL(/\/account\/security/)
    await expect(page.getByText('Two-factor authentication').first()).toBeVisible()
    await page.getByRole('link', { name: 'Set up' }).click()
    await page.waitForURL(/\/two-factor-setup/)
    await enrollTotp(page)
    await page.waitForURL((u) => !u.pathname.startsWith('/two-factor-setup'), { timeout: 30_000 })
    expect(logouts).toEqual([])

    // Back from Account > Security, then into the organization.
    await page.goto(`/auth/continue`)
    await page.waitForURL((u) => u.pathname === '/', { timeout: 30_000 })
    expect(await sessionOrgSlug(page)).toBe(env.E2E_MFA_ORG_SLUG)
  })

  test('a new password account invited into a 2FA organization takes the same step', async ({
    page,
  }) => {
    await page.goto('/login')
    await page.waitForLoadState('networkidle')
    await page.getByLabel('Email').fill(env.E2E_PASSWORD_MFA_EMAIL!)
    await page.getByLabel('Password', { exact: true }).fill(env.E2E_PASSWORD_MFA_PASSWORD!)
    await submitSignIn(page, (url) => !url.pathname.startsWith('/login'))
    await expect(page).toHaveURL(/\/welcome/)
    await page.getByRole('button', { name: 'Join' }).first().click()
    await page.waitForURL(/\/two-factor-setup/, { timeout: 30_000 })
    await enrollTotp(page)
    await page.waitForURL((u) => u.pathname === '/', { timeout: 30_000 })
    expect(await sessionOrgSlug(page)).toBe(env.E2E_MFA_ORG_SLUG)
  })
})
