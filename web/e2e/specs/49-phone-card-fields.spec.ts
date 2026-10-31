import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Phone cards of every list without its own card (DataTable's automatic card:
 * a title, then label/value fields in two columns).
 *
 * Regression guarded (owner report 2026-10-30, /scans/runs on an iPhone): a
 * partial run's status read "Partial 9 unreachable, 373 skipped" on one line
 * that could not wrap, so it ran into the Tasks column beside it. Now:
 *   1. no text inside a field sticks out of the field's column;
 *   2. no two texts of a card overlap;
 *   3. the page never scrolls sideways.
 * The runs list is patched so its first run is partial with a long note and a
 * long scan name, at 390px and 360px. The other routes check whatever the seed
 * has, at 390px.
 */

type Box = { x: number; y: number; right: number; bottom: number; text: string; owner: number }

/** Line boxes of the visible text under `root`, tagged with their text node. */
async function textBoxes(root: Locator): Promise<Box[]> {
  return root.evaluate((el) => {
    const out: Box[] = []
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT)
    let i = 0
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = (n.textContent ?? '').trim()
      const parent = n.parentElement
      if (!text || !parent || parent.closest('.sr-only')) continue
      const style = getComputedStyle(parent)
      if (style.visibility === 'hidden' || style.display === 'none') continue
      const range = document.createRange()
      range.selectNodeContents(n)
      for (const r of Array.from(range.getClientRects())) {
        if (r.width < 1 || r.height < 1) continue
        out.push({ x: r.left, y: r.top, right: r.right, bottom: r.bottom, text, owner: i })
      }
      i += 1
    }
    return out
  }) as Promise<Box[]>
}

function overlaps(boxes: Box[]): string[] {
  const found: string[] = []
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i]
      const b = boxes[j]
      if (a.owner === b.owner) continue
      if (a.x + 1 < b.right && b.x + 1 < a.right && a.y + 1 < b.bottom && b.y + 1 < a.bottom)
        found.push(`"${a.text}" overlaps "${b.text}"`)
    }
  }
  return found
}

/** Texts of a field drawn past its column (the field box is the column). */
async function spills(field: Locator): Promise<string[]> {
  const box = await field.boundingBox()
  if (!box) return []
  return (await textBoxes(field))
    .filter((b) => b.right > box.x + box.width + 1 || b.x < box.x - 1)
    .map((b) => `"${b.text}" sticks out of its field`)
}

async function checkCards(page: Page, at: string) {
  const cards = page.locator('[data-slot="mobile-card"]')
  const n = Math.min(await cards.count(), 10)
  for (let i = 0; i < n; i++) {
    const card = cards.nth(i)
    await card.scrollIntoViewIfNeeded()
    expect.soft(overlaps(await textBoxes(card)), `${at}: card ${i}`).toEqual([])
    const fields = card.locator('[data-slot="mobile-card-field"]')
    const m = await fields.count()
    for (let j = 0; j < m; j++) {
      expect.soft(await spills(fields.nth(j)), `${at}: card ${i} field ${j}`).toEqual([])
    }
  }
  const sideways = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth
  )
  expect.soft(sideways, `${at}: the page does not scroll sideways`).toBeLessThanOrEqual(0)
  return n
}

const LONG_NAME = 'External perimeter recon for every production hostname of the payments platform'

/** First run of the list: partial, with targets it could not scan, and a long name. */
async function patchRuns(page: Page) {
  await page.route(
    (url) => url.pathname === '/api/v1/scan-runs',
    async (route) => {
      const response = await route.fetch()
      const json = await response.json()
      const rows = (json.data ?? json.items ?? []) as Record<string, unknown>[]
      if (rows[0]) {
        Object.assign(rows[0], {
          status: 'partial',
          unreachable_target_count: 9,
          skipped_target_count: 373,
          scan_name: LONG_NAME,
          name: LONG_NAME,
        })
      }
      await route.fulfill({ response, json })
    }
  )
}

for (const width of [390, 360] as const) {
  test(
    `run cards at ${width}px: a long status note wraps inside its column`,
    { tag: ['@scans'] },
    async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 844 })
      await patchRuns(page)
      const res = page.waitForResponse(
        (r) => new URL(r.url()).pathname === '/api/v1/scan-runs' && r.ok(),
        { timeout: 60_000 }
      )
      await page.goto('/scans/runs')
      const body = (await (await res).json()) as { data?: unknown[] }
      test.skip((body.data?.length ?? 0) === 0, 'Needs at least one scan run')

      const partial = page
        .locator('[data-slot="mobile-card"]')
        .filter({ hasText: '9 unreachable, 373 skipped' })
        .first()
      await expect(partial).toBeVisible({ timeout: 45_000 })
      // The state word stays one chip; the note is muted text beside it.
      await expect(partial.locator('[data-slot="health-status"]').first()).not.toContainText(
        'unreachable'
      )
      expect(await checkCards(page, `/scans/runs at ${width}px`)).toBeGreaterThan(0)

      await partial.scrollIntoViewIfNeeded()
      await testInfo.attach(`runs-${width}.png`, {
        body: await page.screenshot(),
        contentType: 'image/png',
      })
    }
  )
}

const ROUTES = [
  '/scans/runs',
  '/scans/workflows',
  '/findings/imports',
  '/remediation/campaigns',
  '/sensors',
  '/settings/members',
  '/settings/audit-log',
  '/settings/api-keys',
  '/attack-surface/certificates',
  '/attack-surface/exposures',
  '/validation/retests',
]

test(
  'automatic phone cards fit their columns on the main lists',
  { tag: ['@shell'] },
  async ({ page }) => {
    test.setTimeout(240_000)
    await page.setViewportSize({ width: 390, height: 844 })
    for (const route of ROUTES) {
      await page.goto(route)
      await expect(page.locator('main').first()).toBeVisible({ timeout: 45_000 })
      await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => {})
      await checkCards(page, `${route} at 390px`)
    }
  }
)
