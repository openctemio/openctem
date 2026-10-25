import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Sensors > Enrollment tokens (research/280): the tab lists the
 * organization's tokens and the create form, fits a phone with no sideways
 * scroll and has no serious or critical accessibility violation. Nothing is
 * created (creating needs a fresh re-authentication).
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

async function seriousAxeIn(page: Page, selector: string) {
  await page.addScriptTag({ path: AXE })
  const result = await page.evaluate(async (sel) => {
    const w = window as unknown as {
      axe: {
        run: (
          ctx: unknown,
          opts: unknown
        ) => Promise<{
          violations: Array<{
            id: string
            impact: string | null
            nodes: Array<{ target: string[] }>
          }>
        }>
      }
    }
    return w.axe.run({ include: [[sel]] }, { resultTypes: ['violations'] })
  }, selector)
  return result.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
}

for (const width of [1440, 390]) {
  test(`enrollment tokens tab and create form at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await page.goto('/sensors?tab=tokens')
    const panel = page.getByTestId('enrollment-tokens')
    await expect(panel).toBeVisible({ timeout: 30_000 })
    await expect(panel.getByText('Enrollment tokens').first()).toBeVisible()
    expect(await seriousAxeIn(page, 'main#content')).toEqual([])

    await panel.getByRole('button', { name: 'Create token' }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog.getByLabel('Name')).toBeVisible()
    await expect(dialog.getByRole('button', { name: 'Create token' })).toBeDisabled()
    const sideways = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth
    )
    expect(sideways).toBeLessThanOrEqual(0)
    expect(await seriousAxeIn(page, '[role=dialog]')).toEqual([])
  })
}
