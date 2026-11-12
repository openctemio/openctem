import { test, expect, type Page, type Request } from '@playwright/test'
import { submitSignIn } from '../helpers/auth'

/**
 * Switching organization leaves nothing of the previous one
 * (web/docs/organization-switch.md).
 *
 * Regression this guards: on "Findings, page 5, filtered" in organization A,
 * switching to B kept the address (page 5 and A's filters), the page state
 * and A's ids in the URL of a detail page, and B's session was then asked
 * for A's page and records. Now the address goes to the section's list root
 * without a query, the page mounts again with a fresh data cache, no request
 * after the switch carries an id of A, and a second tab of the same browser
 * follows the switch.
 *
 * Needs the account in two organizations from web/e2e/ci/seed.sh
 * (E2E_SWITCH_*); skipped without it.
 */

const EMAIL = process.env.E2E_SWITCH_EMAIL
const PASSWORD = process.env.E2E_SWITCH_PASSWORD
const ORG_A = process.env.E2E_SWITCH_ORG_A
const ORG_B = process.env.E2E_SWITCH_ORG_B

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi

/** Ids of the findings the current session's organization has. */
async function findingIds(page: Page): Promise<string[]> {
  const res = await page.request.get('/api/v1/findings?per_page=100')
  expect(res.ok()).toBe(true)
  const body = (await res.json()) as { data?: { id: string }[] }
  return (body.data ?? []).map((f) => f.id)
}

async function signInToA(page: Page) {
  await page.goto('/login')
  await page.waitForLoadState('networkidle')
  await page.getByLabel('Email').fill(EMAIL!)
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD!)
  await submitSignIn(page, (url) => !url.pathname.startsWith('/login'))
  if (new URL(page.url()).pathname.startsWith('/select-tenant')) {
    await page.getByRole('button', { name: new RegExp(ORG_A!) }).click()
    await page.waitForURL((url) => !url.pathname.startsWith('/select-tenant'), { timeout: 30_000 })
  }
}

async function switchTo(page: Page, org: string) {
  await page.getByTestId('team-switcher-trigger').click()
  const item = page.getByTestId('org-card-switch-item').filter({ hasText: org })
  await expect(item).toBeVisible({ timeout: 15_000 })
  const switched = page.waitForResponse((r) => r.url().includes('/api/auth/switch-team') && r.ok())
  await item.click()
  await switched
}

/** Every request the page sends from now on (URL and body). */
function recordRequests(page: Page): string[] {
  const seen: string[] = []
  page.on('request', (r: Request) => {
    if (!r.url().includes('/api/')) return
    seen.push(`${r.method()} ${r.url()} ${r.postData() ?? ''}`)
  })
  return seen
}

function carryingAny(requests: string[], ids: string[]): string[] {
  return requests.filter((r) => (r.match(UUID) ?? []).some((id) => ids.includes(id.toLowerCase())))
}

test.describe('organization switch', () => {
  test.skip(!EMAIL || !PASSWORD || !ORG_A || !ORG_B, 'Set E2E_SWITCH_* (web/e2e/ci/seed.sh)')

  test(
    'leaves nothing of the previous organization: address, rows, requests, other tabs',
    { tag: ['@shell', '@findings'] },
    async ({ page, context }) => {
      test.setTimeout(180_000)
      await signInToA(page)

      const idsOfA = (await findingIds(page)).map((id) => id.toLowerCase())
      expect(idsOfA.length).toBeGreaterThanOrEqual(41)

      await test.step('Findings, page 5, filtered, in A -> switch to B', async () => {
        const list = page.waitForResponse((r) => /\/api\/v1\/findings\?/.test(r.url()) && r.ok())
        // Page 4, then page 5: the back button returns to page 4 later.
        await page.goto('/findings?page=4&per_page=10')
        await expect(page.locator('a[href^="/findings/"]').first()).toBeVisible({
          timeout: 30_000,
        })
        await page.goto('/findings?page=5&per_page=10&severity=high')
        await list
        await expect(page.locator('a[href^="/findings/"]').first()).toBeVisible({
          timeout: 30_000,
        })

        // A second tab of the same browser, on another page of A.
        const other = await context.newPage()
        await other.goto('/findings?page=2&per_page=10')
        await expect(other.locator('a[href^="/findings/"]').first()).toBeVisible({
          timeout: 30_000,
        })

        const after = recordRequests(page)
        const afterOther = recordRequests(other)
        await switchTo(page, ORG_B!)

        await expect(page.getByText(`Switched to ${ORG_B}`)).toBeVisible({ timeout: 15_000 })
        await expect(page).toHaveURL((url) => url.pathname === '/findings' && url.search === '', {
          timeout: 15_000,
        })

        const idsOfB = (await findingIds(page)).map((id) => id.toLowerCase())
        expect(idsOfB.length).toBeGreaterThan(0)
        expect(idsOfB.filter((id) => idsOfA.includes(id))).toEqual([])

        // B's rows on page 1; no row of A at any point after the landing.
        await expect(page.locator(`a[href="/findings/${idsOfB[0]}"]`).first()).toBeVisible({
          timeout: 30_000,
        })
        for (const id of idsOfA) {
          await expect(page.locator(`a[href^="/findings/${id}"]`)).toHaveCount(0)
        }
        // Nothing sent after the switch named a finding of A or asked for page 5.
        const switchedAt = after.findIndex((r) => r.includes('/api/auth/switch-team'))
        const sinceSwitch = after.slice(switchedAt + 1)
        expect(carryingAny(sinceSwitch, idsOfA)).toEqual([])
        expect(sinceSwitch.filter((r) => /[?&]page=5\b/.test(r))).toEqual([])

        // The other tab followed: list root, the notice, no row of A.
        await other.bringToFront()
        await expect(other).toHaveURL((url) => url.pathname === '/findings' && url.search === '', {
          timeout: 15_000,
        })
        await expect(other.getByText(`Another tab switched to ${ORG_B}`)).toBeVisible({
          timeout: 15_000,
        })
        for (const id of idsOfA.slice(0, 10)) {
          await expect(other.locator(`a[href^="/findings/${id}"]`)).toHaveCount(0)
        }
        expect(carryingAny(afterOther, idsOfA)).toEqual([])
        await other.close()

        // Back: the browser returns to A's page 4, which is not shown again.
        await page.goBack()
        await expect(page).toHaveURL((url) => url.pathname === '/findings' && url.search === '', {
          timeout: 15_000,
        })
        for (const id of idsOfA.slice(0, 10)) {
          await expect(page.locator(`a[href^="/findings/${id}"]`)).toHaveCount(0)
        }
      })

      await test.step("a finding of B open -> switch to A lands on A's list", async () => {
        const idsOfB = (await findingIds(page)).map((id) => id.toLowerCase())
        await page.goto(`/findings/${idsOfB[0]}`)
        await expect(page).toHaveURL(new RegExp(`/findings/${idsOfB[0]}`))

        const after = recordRequests(page)
        await switchTo(page, ORG_A!)
        await expect(page.getByText(`Switched to ${ORG_A}`)).toBeVisible({ timeout: 15_000 })
        await expect(page).toHaveURL((url) => url.pathname === '/findings' && url.search === '', {
          timeout: 15_000,
        })
        const switchedAt = after.findIndex((r) => r.includes('/api/auth/switch-team'))
        expect(carryingAny(after.slice(switchedAt + 1), idsOfB)).toEqual([])
      })
    }
  )
})
