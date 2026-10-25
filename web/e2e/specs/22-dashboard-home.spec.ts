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
      // copy of the CTEM template) is shown.
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

test('a new user lands on the exposure flow and its CTEM stages', async ({ page }) => {
  test.setTimeout(240_000)
  // The e2e seed gives the user no dashboard: the first visit stores a
  // personal copy of the CTEM template, computed in their own scope.
  await page.goto('/')
  await expect(page.getByTestId('dashboard-freshness')).toBeVisible({ timeout: 45_000 })
  // The five stages are part of the exposure flow at the top of the template.
  const loop = page.getByRole('list', { name: 'CTEM stage health' })
  // A new organization's first fact build runs in the background (the
  // maintainer's reconcile tick, up to a minute or two) and the widgets say
  // "No data yet" until it is done. Refresh now recomputes the figures from
  // whatever the build has finished; a refresh too soon after the last one is
  // refused, which only costs another round.
  await expect(async () => {
    if (!(await loop.isVisible())) {
      const refresh = page.getByRole('button', { name: 'Refresh now' })
      if (await refresh.isEnabled()) await refresh.click()
    }
    await expect(loop).toBeVisible({ timeout: 8_000 })
  }).toPass({ timeout: 180_000, intervals: [2_000, 5_000, 10_000] })
  const stages = loop.getByRole('listitem')
  await expect(stages).toHaveCount(5)
  for (const name of ['Scoping', 'Discovery', 'Prioritize', 'Validate', 'Mobilize']) {
    await expect(loop.getByText(name, { exact: true })).toBeVisible()
  }
  // At most one stage is the place to act.
  expect(await loop.locator('[aria-current="step"]').count()).toBeLessThanOrEqual(1)
  await expect(page.getByText('Attack paths to crown jewels')).toBeVisible()
})
