import path from 'path'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The exposure flow and the intake on the dashboard (api
 * docs/architecture/dashboards.md, "Exposure flow and intake"): at phone and
 * desktop width, in light and dark, the flow renders with no serious or
 * critical accessibility violations and no horizontal page scroll; a figure
 * opens its tooltip on keyboard focus with the same list as the figure, and
 * Escape closes it; the receipt list the intake figures open loads with the
 * totals of its filter.
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
    test(`exposure flow at ${vp.name} width in ${scheme}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width: vp.width, height: vp.height })
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
      await page.goto('/')
      const flow = page.getByTestId('exposure-flow').first()
      await expect(flow).toBeVisible({ timeout: 45_000 })
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
          { include: [['[data-testid="exposure-flow"]']] },
          { resultTypes: ['violations'] }
        )
      })) as AxeResult
      const serious = result.violations
        .filter((v) => v.impact === 'serious' || v.impact === 'critical')
        .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
      expect(serious).toEqual([])

      // Keyboard focus opens the tooltip; its link is the figure's own list.
      const open = flow.locator('[data-k="o:open"]')
      const href = await open.getAttribute('href')
      await open.focus()
      const tip = page.getByRole('tooltip')
      await expect(tip).toBeVisible()
      await expect(open).toHaveAttribute('aria-describedby', (await tip.getAttribute('id')) ?? '')
      if (href) await expect(tip.getByRole('link')).toHaveAttribute('href', href)
      await page.keyboard.press('Escape')
      await expect(tip).toBeHidden()

      await testInfo.attach(`exposure-flow-${vp.name}-${scheme}.png`, {
        body: await flow.screenshot(),
        contentType: 'image/png',
      })
    })
  }
}

test(
  'the receipt list opens with the totals of its filter',
  { tag: ['@dashboard'] },
  async ({ page }) => {
    await page.goto('/findings/imports?origin=sensor')
    await expect(page.getByRole('heading', { name: 'Import and run receipts' })).toBeVisible({
      timeout: 45_000,
    })
    await expect(page.getByTestId('receipt-totals')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Remove filter Sensor' })).toBeVisible()
    await page.getByRole('button', { name: 'Remove filter Sensor' }).click()
    await expect(page).toHaveURL(/\/findings\/imports$/)
  }
)
