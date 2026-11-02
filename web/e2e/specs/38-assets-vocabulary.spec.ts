import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Asset vocabulary and the phone card (research/271).
 *
 * - Criticality and risk never read as the same word: a risk cell shows its
 *   number (band as colour, shape and tooltip), and on a phone card, which
 *   has no column headers, criticality names itself ("Criticality: High")
 *   and the risk number sits under the word "Risk".
 * - The findings count is "N open findings" everywhere, and the list its link
 *   opens has the same total.
 * - The phone card is one meta line, its findings link is a 44 px touch
 *   target, there is no horizontal page scroll, and axe finds no serious
 *   violation in light or dark.
 *
 * Tagged @phone: the webkit-mobile project (E2E_WEBKIT=1, iPhone 13) runs the
 * phone tests too.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')
const BAND = /\b(Critical|High|Medium|Low|Minimal)\b/

interface AxeResult {
  violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
}

async function seriousViolations(page: Page) {
  await page.addScriptTag({ path: AXE })
  const result = (await page.evaluate(async () => {
    const w = window as unknown as {
      axe: { run: (ctx: unknown, opts: unknown) => Promise<AxeResult> }
    }
    return w.axe.run({ include: [['main#content']] }, { resultTypes: ['violations'] })
  })) as AxeResult
  return result.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
}

interface ListedAsset {
  id: string
  name: string
  finding_count: number
}

/** Opens /assets (sorted by open findings) and returns the list response rows. */
async function openAssets(page: Page): Promise<ListedAsset[]> {
  const listed = page.waitForResponse(
    (r) => /\/api\/v1\/assets\?/.test(r.url()) && r.request().method() === 'GET' && r.ok(),
    { timeout: 45_000 }
  )
  await page.goto('/assets?sort=-finding_count')
  const body = (await (await listed).json()) as { data?: ListedAsset[] }
  await page.waitForLoadState('networkidle')
  return body.data ?? []
}

test.describe('phone card @phone', { tag: ['@assets'] }, () => {
  test.beforeEach(async ({ page }, testInfo) => {
    // The webkit-mobile project brings its own iPhone viewport.
    if (testInfo.project.name === 'chromium')
      await page.setViewportSize({ width: 390, height: 844 })
  })

  for (const scheme of ['light', 'dark'] as const) {
    test(`one meta line, named criticality and risk, no h-scroll, axe (${scheme})`, async ({
      page,
    }, testInfo) => {
      await page.emulateMedia({ colorScheme: scheme })
      const rows = await openAssets(page)
      test.skip(rows.length === 0, 'no seeded assets')

      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth
      )
      expect(overflow, 'horizontal page scroll on a phone').toBeLessThanOrEqual(0)

      // A real score sits at the card's right edge under the word "Risk".
      const risk = page.locator('[data-slot="asset-card-risk"]').first()
      if (await risk.count()) await expect(risk).toHaveText(/^Risk\s*\d+(\.\d)?$/)

      const metas = page.locator('[data-slot="asset-card-meta"]')
      await expect(metas.first()).toBeVisible()
      const n = Math.min(await metas.count(), 6)
      for (let i = 0; i < n; i++) {
        const meta = metas.nth(i)
        const text = (await meta.innerText()).replace(/\s+/g, ' ')
        // Criticality names itself; a band word never stands alone.
        expect(text).toMatch(/Criticality: /)
        const bare = text.replace(/Criticality: \w+/, '')
        expect(bare, `a bare band word on card ${i}: "${text}"`).not.toMatch(BAND)
        // One meta line (the 22 px pill sets its height).
        const box = await meta.boundingBox()
        expect(box?.height ?? 0).toBeLessThanOrEqual(28)
      }

      expect(await seriousViolations(page)).toEqual([])
      await testInfo.attach(`assets-phone-${scheme}.png`, {
        body: await page.screenshot(),
        contentType: 'image/png',
      })
    })
  }

  test('"N open findings" matches the list it opens, with a 44 px touch target', async ({
    page,
  }) => {
    const rows = await openAssets(page)
    test.skip(!rows.some((r) => r.finding_count > 0), 'no seeded asset with open findings')

    // Read the card itself, not the list response: other specs in the run
    // open and close findings concurrently, so a count snapshot taken from
    // the response can differ from the card by the time it renders. The
    // invariant under test is that the card's number is the list it opens.
    const link = page
      .locator('[data-slot="asset-card-meta"] [data-slot="open-findings-link"]')
      .first()
    await expect(link).toBeVisible()
    const label = (await link.textContent()) ?? ''
    const shown = /^(\d+) open findings?$/.exec(label.trim())
    expect(shown, `card label "${label}"`).not.toBeNull()
    const count = Number(shown![1])
    const assetId = new URL((await link.getAttribute('href')) ?? '', 'http://x').searchParams.get(
      'asset_id'
    )
    expect(assetId).toBeTruthy()

    // The hit area reaches 44 px tall: points 20 px above and below the
    // centre still land on the link.
    const box = await link.boundingBox()
    expect(box).not.toBeNull()
    const hits = await page.evaluate(
      ({ x, y }) =>
        [y - 20, y + 20].map((py) => {
          const el = document.elementFromPoint(x, py)
          return !!el?.closest('[data-slot="open-findings-link"]')
        }),
      { x: box!.x + box!.width / 2, y: box!.y + box!.height / 2 }
    )
    expect(hits).toEqual([true, true])

    const listed = page.waitForResponse(
      (r) => /\/api\/v1\/findings\?/.test(r.url()) && r.url().includes(assetId!) && r.ok(),
      { timeout: 45_000 }
    )
    await link.click()
    await expect(page).toHaveURL(/\/findings\?.*asset_id=/)
    const findings = (await (await listed).json()) as { total?: number }
    expect(findings.total).toBe(count)
  })
})

test(
  'desktop: risk cells show the number, "Open findings" column, axe',
  { tag: ['@assets'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    const rows = await openAssets(page)
    test.skip(rows.length === 0, 'no seeded assets')

    await expect(page.getByRole('columnheader', { name: /^Open findings/ })).toHaveCount(1)
    await expect(page.getByRole('columnheader', { name: /^Findings/ })).toHaveCount(0)
    const risk = page.locator(
      'main tbody tr [data-slot="severity-badge"][data-score]:not([data-score="0"])'
    )
    const count = await risk.count()
    for (let i = 0; i < Math.min(count, 10); i++) {
      const cell = risk.nth(i)
      await expect(cell).toHaveText(/^\d+(\.\d)?$/)
      await expect(cell).toHaveAttribute('aria-label', /^Risk \d/)
    }
    expect(await seriousViolations(page)).toEqual([])
  }
)
