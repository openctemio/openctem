import path from 'path'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The exposure flow and the intake on the dashboard (api
 * docs/architecture/dashboards.md, "Exposure flow and intake"): at phone and
 * desktop width, in light and dark, the flow renders with no serious or
 * critical accessibility violations and no horizontal page scroll; a figure
 * opens its tooltip on keyboard focus with the same list as the figure, and
 * Escape closes it; the receipt list the intake figures open loads with the
 * totals of its filter. On a phone the answer comes first (actionable now,
 * outcomes, stages, then sources), the actionable total shows once, and every
 * figure is a tap target of at least 44 px; on a desktop the rings stay (each
 * with its track, a source arc explains itself on focus) and the funnel no
 * longer repeats the actionable total (research/359).
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
    test(
      `exposure flow at ${vp.name} width in ${scheme}`,
      { tag: ['@dashboard'] },
      async ({ page }, testInfo) => {
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

        // The actionable total shows once (the ring centre or the phone headline).
        await expect(flow.getByTestId('flow-centre')).toHaveCount(1)
        await expect(flow.getByText(/not part of the period/)).toHaveCount(0)

        if (vp.width < 768) {
          await expect(flow).toHaveAttribute('data-band', 'narrow')
          const order = await flow.evaluate((el) =>
            [...el.querySelectorAll('[data-testid]')]
              .map((n) => n.getAttribute('data-testid'))
              .filter((id) =>
                ['flow-headline', 'flow-outcomes', 'flow-stages', 'flow-sources'].includes(id ?? '')
              )
          )
          expect(order.slice(0, 2), 'phone: the answer first').toEqual([
            'flow-headline',
            'flow-outcomes',
          ])
          // Every figure (link) in the flow is at least 44 px tall to tap.
          const small = await flow.evaluate((el) =>
            [...el.querySelectorAll('a[href], [role="link"]')]
              .map((n) => ({
                t: (n.textContent ?? '').trim().slice(0, 30),
                h: n.getBoundingClientRect().height,
              }))
              .filter((x) => x.h > 0 && x.h < 43.5)
          )
          expect(small, 'phone tap targets under 44 px').toEqual([])
        } else {
          await expect(flow.locator('svg[role="group"]')).toBeVisible()
          // Every ring has its track, so an empty ring still reads as a ring.
          expect(await flow.locator('[data-testid="ring-track"]').count()).toBeGreaterThan(0)
          // A source arc (organization read with sources) explains itself on focus.
          const arc = flow.locator('[data-seg^="s:"][role="link"]').first()
          if (await arc.count()) {
            await arc.focus()
            await expect(page.getByRole('tooltip').getByText('Share of received')).toBeVisible()
            await page.keyboard.press('Escape')
          }
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
      }
    )
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
