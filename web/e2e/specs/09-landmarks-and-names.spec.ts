import { test as base } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { loginAs } from '../helpers/auth'
import { getE2EConfig } from '../helpers/env'
import { axeRuleViolations } from '../helpers/axe'

/**
 * Landmarks and accessible names.
 *
 * Regressions this guards:
 *   1. Every dashboard page had two nested `main` landmarks (the layout's
 *      and the page's <Main>).
 *   2. The Access Denied view had no `main` landmark and no #content, so
 *      "Skip to Main" led nowhere.
 *   3. The "Require two-factor authentication" switch had no accessible name.
 *      (The "Restricted data scope" switch it was checked with is gone: it
 *      never saved, and Teams > Members without a team replaced it.)
 *
 * The Access Denied check needs a user without team:update (a member or
 * viewer): set E2E_LIMITED_EMAIL / E2E_LIMITED_PASSWORD, or it is skipped.
 */

test.describe('Landmarks', { tag: ['@shell'] }, () => {
  test('dashboard pages have exactly one main landmark, and it is #content', async ({ page }) => {
    for (const path of ['/', '/findings', '/sensors', '/settings/general']) {
      await page.goto(path)
      await expect(page.locator('main#content'), path).toHaveCount(1, { timeout: 30_000 })
      await expect(page.getByRole('main'), path).toHaveCount(1)
    }
  })
})

base.describe('Access denied view', { tag: ['@shell'] }, () => {
  base('is the main landmark and the skip link target', async ({ page }) => {
    const cfg = getE2EConfig()
    const email = process.env.E2E_LIMITED_EMAIL
    const password = process.env.E2E_LIMITED_PASSWORD
    base.skip(!cfg.ok || !email || !password, 'Set E2E_LIMITED_EMAIL / E2E_LIMITED_PASSWORD')
    if (!cfg.ok) return

    await loginAs(page, { ...cfg.config, userEmail: email!, userPassword: password! })
    await page.goto('/settings/general')
    await expect(page.getByText('Access Denied', { exact: true })).toBeVisible({ timeout: 30_000 })

    await expect(page.getByRole('main')).toHaveCount(1)
    await expect(page.locator('main#content')).toContainText('Access Denied')

    // The skip link is the first stop and lands on the denied view.
    await page.keyboard.press('Tab')
    await expect(page.getByRole('link', { name: 'Skip to main content' })).toBeFocused()
  })
})

test.describe('Organization authentication settings', { tag: ['@shell'] }, () => {
  test('each two-factor switch has its own accessible name', async ({ page }) => {
    await page.goto('/settings/authentication')
    // Everyone, and owners and administrators only (#1413): two switches, two names
    // (the card title above them says two-factor).
    await expect(
      page.getByRole('switch', { name: 'Require for everyone', exact: true })
    ).toBeVisible({ timeout: 30_000 })
    await expect(
      page.getByRole('switch', {
        name: 'Require for owners and administrators',
        exact: true,
      })
    ).toBeVisible()
  })
})

/**
 * A control named by an aria-label contains its visible label (WCAG 2.5.3,
 * label in name): the organization switcher (its initials chip only repeats
 * the name), the search button (its shortcut hint is hidden and stated as
 * aria-keyshortcuts), the Triage button and each finding row (its title is
 * the open button). Before: 2 violations on every page, 12 on /findings.
 */
test.describe('Label in name', { tag: ['@shell', '@findings'] }, () => {
  test('shell and findings list controls contain their visible label', async ({ page }) => {
    for (const path of ['/', '/findings']) {
      await page.goto(path)
      await expect(page.locator('main#content')).toBeVisible({ timeout: 30_000 })
      await page.waitForLoadState('networkidle')
      expect(await axeRuleViolations(page, ['label-content-name-mismatch']), path).toEqual([])
    }
  })
})

test.describe('Finding properties markup', { tag: ['@findings'] }, () => {
  test('the properties are valid description lists', async ({ page }) => {
    const res = page.waitForResponse((r) => /\/api\/v1\/findings\?/.test(r.url()) && r.ok(), {
      timeout: 60_000,
    })
    await page.goto('/findings')
    const body = (await (await res).json()) as { data?: Array<{ id: string }> }
    const id = body.data?.[0]?.id
    test.skip(!id, 'Needs a finding')
    await page.goto(`/findings/${id}`)
    await expect(page.getByRole('group', { name: 'Properties' })).toBeVisible({ timeout: 30_000 })
    await page.waitForLoadState('networkidle')
    // Before: the People group and the folded rows sat inside the dl (14 nodes).
    expect(await axeRuleViolations(page, ['definition-list', 'dlitem'])).toEqual([])
  })
})

test.describe('Links in running text', { tag: ['@shell', '@attack-surface'] }, () => {
  test('/scope tells its in-text link apart without relying on colour', async ({ page }) => {
    await page.goto('/scope')
    await expect(page.locator('main#content')).toBeVisible({ timeout: 30_000 })
    await page.waitForLoadState('networkidle')
    // Before: the link colour was 2.3:1 against the text around it, no underline.
    expect(await axeRuleViolations(page, ['link-in-text-block'])).toEqual([])
  })
})
