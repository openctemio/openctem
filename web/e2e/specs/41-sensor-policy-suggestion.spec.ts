import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * A sensor that refuses network jobs for lack of a local policy offers the
 * suggested policy in its drawer as one host command (research/283 X-1, X-2),
 * readable on a phone and a desktop, with no serious axe violation.
 *
 * Needs the CI seed: e2e-sensor reports `local_policy: absent, required`.
 * Read-only.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

const SIZES = [
  { name: 'phone', width: 390, height: 844 },
  { name: 'desktop', width: 1440, height: 900 },
]

async function seriousAxeIn(page: Page, selector: string) {
  await page.addScriptTag({ path: AXE })
  const violations = await page.evaluate(async (sel) => {
    const w = window as unknown as {
      axe: {
        run: (
          ctx: unknown,
          opts: unknown
        ) => Promise<{ violations: Array<{ id: string; impact: string | null }> }>
      }
    }
    const r = await w.axe.run({ include: [[sel]] }, { resultTypes: ['violations'] })
    return r.violations
  }, selector)
  return violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => v.id)
}

for (const size of SIZES) {
  test(
    `suggested local policy in the sensor drawer (${size.name})`,
    { tag: ['@sensors'] },
    async ({ page }) => {
      await page.setViewportSize({ width: size.width, height: size.height })
      await page.goto('/sensors')
      const name = page.locator('[data-slot="sensor-name"]', { hasText: /^e2e-sensor$/ }).first()
      const found = await name
        .waitFor({ timeout: 30_000 })
        .then(() => true)
        .catch(() => false)
      test.skip(!found, 'No e2e-sensor in the organization (not the CI seed)')
      await name.click()
      const sheet = page.locator('[data-slot="detail-sheet"]')
      await expect(sheet).toBeVisible()

      await expect(sheet.getByText('Network scans refused: no local policy')).toBeVisible({
        timeout: 15_000,
      })
      const block = sheet.getByTestId('policy-suggestion')
      await block.scrollIntoViewIfNeeded()
      await expect(block).toBeVisible({ timeout: 15_000 })
      await expect(block.locator('pre')).toContainText(
        "sudo tee /etc/openctem/sensor-policy.yaml >/dev/null <<'OPENCTEM_POLICY'"
      )
      await expect(block.locator('pre')).toContainText('apiVersion: openctem.io/sensor-policy/v1')
      await expect(block.getByRole('button', { name: /copy/i })).toBeVisible()

      // The block stays inside the drawer: its code scrolls, the page does not.
      const fits = await block.evaluate((el) => {
        const sheetEl = el.closest('[data-slot="detail-sheet"]')
        if (!sheetEl) return false
        const b = el.getBoundingClientRect()
        const s = sheetEl.getBoundingClientRect()
        return b.left >= s.left - 1 && b.right <= s.right + 1
      })
      expect(fits).toBe(true)

      expect(await seriousAxeIn(page, '[data-testid="policy-suggestion"]')).toEqual([])
    }
  )
}
