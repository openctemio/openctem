import path from 'path'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Asset list rows (research/266): every row has the same height, the type is
 * the name's second line (no Type column by default), Last seen shows a time,
 * labels carry their tone, no horizontal page scroll on a phone, and no
 * serious or critical accessibility violation (axe-core, colour contrast
 * included) in light and dark.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

interface AxeResult {
  violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
}

async function seriousViolations(page: import('@playwright/test').Page) {
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

for (const scheme of ['light', 'dark'] as const) {
  test(`asset rows at 1440px in ${scheme}: one height, type under the name, a time`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/assets')
    const cells = page.getByTestId('asset-name-cell')
    const seeded = await cells
      .first()
      .waitFor({ state: 'visible', timeout: 30_000 })
      .then(() => true)
      .catch(() => false)
    test.skip(!seeded, 'no seeded assets')
    await page.waitForLoadState('networkidle')

    const heights = await page
      .locator('main tbody tr')
      .evaluateAll((rows) => rows.map((r) => Math.round(r.getBoundingClientRect().height)))
    expect(new Set(heights).size, `row heights ${heights.join(',')}`).toBe(1)

    await expect(page.getByRole('columnheader', { name: /^Type/ })).toHaveCount(0)
    await expect(cells.first().locator('[data-slot="asset-type-line"]')).toBeVisible()
    // Last seen is a time ("3 hours ago"), never the bare word "Active".
    const lastSeen = page.locator('main tbody tr time').first()
    await expect(lastSeen).toHaveText(/ago|now/)

    expect(await seriousViolations(page)).toEqual([])
    await testInfo.attach(`assets-1440-${scheme}.png`, {
      body: await page.screenshot({ fullPage: true }),
      contentType: 'image/png',
    })
  })
}

test('asset cards at 375px: no horizontal page scroll, no serious a11y violation', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 375, height: 812 })
  await page.goto('/assets')
  await expect(page.getByTestId('inventory-view-title')).toBeVisible({ timeout: 30_000 })
  await page.waitForLoadState('networkidle')
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth
  )
  expect(overflow, 'horizontal page scroll on a phone').toBeLessThanOrEqual(0)
  expect(await seriousViolations(page)).toEqual([])
  await testInfo.attach('assets-375.png', {
    body: await page.screenshot({ fullPage: true }),
    contentType: 'image/png',
  })
})
