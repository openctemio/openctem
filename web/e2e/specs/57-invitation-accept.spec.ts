import { test, expect, type Page } from '@playwright/test'
import { submitSignIn } from '../helpers/auth'

/**
 * Accepting an invitation lands in the organization just joined.
 *
 * Regression this guards: Accept added the membership but left the session
 * on the previous organization (or none), then moved client-side to `/`. An
 * account with its own organization landed in that one; an account without
 * one was sent to /welcome ("you are not in an organization yet"), and
 * opening the link again showed "Invitation already accepted" with only
 * "Go to sign in". Now Accept selects the invited organization and loads
 * its home as a new page, with "You joined <organization>." shown there, and
 * an accepted invitation offers "Open <organization>".
 *
 * Needs the invitees from web/e2e/ci/seed.sh (E2E_INVITEE_*); skipped
 * without them. Each invitation can be accepted once: run against a fresh seed.
 */

const ORG = process.env.E2E_INVITE_ORG
const SLUG = process.env.E2E_INVITE_ORG_SLUG
const HOME_ORG = process.env.E2E_INVITEE_HOME_ORG
const WITH_ORG = {
  email: process.env.E2E_INVITEE_EMAIL,
  password: process.env.E2E_INVITEE_PASSWORD,
  token: process.env.E2E_INVITEE_TOKEN,
}
const WITHOUT_ORG = {
  email: process.env.E2E_INVITEE_NEW_EMAIL,
  password: process.env.E2E_INVITEE_NEW_PASSWORD,
  token: process.env.E2E_INVITEE_NEW_TOKEN,
}

async function signIn(page: Page, email: string, password: string) {
  await page.goto('/login')
  await page.waitForLoadState('networkidle')
  await page.getByLabel('Email').fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await submitSignIn(page, (url) => !url.pathname.startsWith('/login'))
}

/** The organization the session cookie names (slug), or null. */
async function sessionOrgSlug(page: Page): Promise<string | null> {
  const cookie = (await page.context().cookies()).find((c) => c.name === 'app_tenant')
  if (!cookie) return null
  try {
    return (JSON.parse(decodeURIComponent(cookie.value)) as { slug?: string }).slug ?? null
  } catch {
    return null
  }
}

async function expectLandedInOrg(page: Page) {
  await page.waitForURL((url) => url.pathname === '/', { timeout: 30_000 })
  expect(await sessionOrgSlug(page)).toBe(SLUG)
  await expect(page.getByText(`You joined ${ORG}.`)).toBeVisible({ timeout: 15_000 })
  // The organization's own shell, not the account space.
  await expect(page.getByTestId('team-switcher-trigger')).toContainText(ORG!)
}

test.describe('invitation accept', { tag: ['@auth'] }, () => {
  test.skip(
    !ORG || !SLUG || !HOME_ORG || !WITH_ORG.token || !WITHOUT_ORG.token,
    'Set E2E_INVITEE_* and E2E_INVITE_ORG* (web/e2e/ci/seed.sh)'
  )
  test.describe.configure({ mode: 'serial' })

  test('an account with its own organization lands in the one it joined', async ({ page }) => {
    await signIn(page, WITH_ORG.email!, WITH_ORG.password!)
    expect(await sessionOrgSlug(page)).not.toBe(SLUG)
    await expect(page.getByTestId('team-switcher-trigger')).toContainText(HOME_ORG!)

    await page.goto(`/invitations#token=${WITH_ORG.token}`)
    await page.getByRole('button', { name: /accept invitation/i }).click()

    await expectLandedInOrg(page)
  })

  test('an account without an organization lands in it too, at phone width', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await signIn(page, WITHOUT_ORG.email!, WITHOUT_ORG.password!)
    await page.waitForURL((url) => url.pathname.startsWith('/welcome'))

    await page.goto(`/invitations#token=${WITHOUT_ORG.token}`)
    await page.getByRole('button', { name: /accept invitation/i }).click()

    await page.waitForURL((url) => url.pathname === '/', { timeout: 30_000 })
    expect(await sessionOrgSlug(page)).toBe(SLUG)
    await expect(page.getByText(`You joined ${ORG}.`)).toBeVisible({ timeout: 15_000 })
    expect(new URL(page.url()).pathname).not.toBe('/welcome')

    // The link again: accepted, with a way into the organization.
    await page.goto(`/invitations#token=${WITHOUT_ORG.token}`)
    await expect(page.getByText('Invitation already accepted')).toBeVisible()
    await page.getByRole('button', { name: `Open ${ORG}` }).click()
    await page.waitForURL((url) => url.pathname === '/', { timeout: 30_000 })
    expect(await sessionOrgSlug(page)).toBe(SLUG)
  })
})
