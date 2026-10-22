import path from 'path'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Dashboard home (research 203, P0-9): at phone and desktop width, in light
 * and dark, the dashboard renders its widgets with no serious or critical
 * accessibility violations (axe-core, colour contrast included outside the
 * chart canvases), no horizontal page scroll on a phone, and a screenshot of
 * each combination attached to the report for visual review.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

interface AxeResult {
  violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
}

const VIEWPORTS = [
  { name: 'phone', width: 390, height: 844 },
  { name: 'desktop', width: 1440, height: 900 },
] as const

for (const vp of VIEWPORTS) {
  for (const scheme of ['light', 'dark'] as const) {
    test(`dashboard home at ${vp.name} width in ${scheme}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width: vp.width, height: vp.height })
      await page.emulateMedia({ colorScheme: scheme })
      await page.goto('/')
      // The freshness line appears once a stored dashboard (or the first-visit
      // copy of the Overview template) is shown.
      await expect(page.getByTestId('dashboard-freshness')).toBeVisible({ timeout: 45_000 })
      await expect(page.locator('[data-widget-index]').first()).toBeVisible()
      await page.waitForLoadState('networkidle')

      if (vp.width < 768) {
        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth - document.documentElement.clientWidth
        )
        expect(overflow, 'horizontal page scroll on a phone').toBeLessThanOrEqual(0)
      }

      await page.addScriptTag({ path: AXE })
      const result = (await page.evaluate(async () => {
        const w = window as unknown as {
          axe: { run: (ctx: unknown, opts: unknown) => Promise<AxeResult> }
        }
        return w.axe.run(
          { include: [['main#content']], exclude: [['.recharts-wrapper']] },
          { resultTypes: ['violations'] }
        )
      })) as AxeResult
      const serious = result.violations
        .filter((v) => v.impact === 'serious' || v.impact === 'critical')
        .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
      expect(serious).toEqual([])

      await testInfo.attach(`dashboard-${vp.name}-${scheme}.png`, {
        body: await page.screenshot({ fullPage: true }),
        contentType: 'image/png',
      })
    })
  }
}

test('the dashboard editor is usable with the keyboard', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByTestId('dashboard-freshness')).toBeVisible({ timeout: 45_000 })
  const customize = page.getByRole('button', { name: 'Customize' })
  test.skip(
    (await customize.count()) === 0,
    'the landing dashboard is not editable by the seed user'
  )
  await customize.click()
  const first = page.getByTestId('editor-card').first()
  await first.focus()
  const name = await first.getAttribute('aria-label')
  await page.keyboard.press('ArrowRight')
  await expect(page.getByTestId('editor-announcer')).toContainText('position 2')
  await page.keyboard.press('Control+z')
  await expect(page.getByTestId('editor-card').first()).toHaveAttribute('aria-label', name ?? '')
  await page.getByRole('button', { name: 'Cancel' }).first().click()
  await expect(page.getByTestId('dashboard-freshness')).toBeVisible()
})
