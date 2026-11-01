import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Re-pair a sensor (research/352 D2): Sensors > sensor > More actions >
 * Re-pair... asks why, shows that the current key keeps working (or offers to
 * revoke it for a compromised key), and creates a re-pair code that goes into
 * the install command (no API key). The dialog fits a phone with no sideways
 * scroll and has no serious or critical accessibility violation.
 *
 * Creating a code leaves a re-pair request that expires on its own in 10
 * minutes; the sensor's key and registration are not changed. A newer
 * re-pair code of the same sensor closes the earlier one, so the widths run
 * serially. "Revoke the
 * current key now" is never ticked here.
 */

// Both widths re-pair the same sensor, and a newer re-pair code closes the
// earlier one: the tests run one after the other.
test.describe.configure({ mode: 'serial' })

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

async function openFirstSensor(page: Page) {
  await page.goto('/sensors?mode=daemon')
  await expect(page.getByRole('heading', { name: 'Sensors', level: 1 })).toBeVisible()
  // An active organization sensor, by name: the list renders rows at desktop
  // width and cards on a phone.
  const res = await page.request.get('/api/v1/sensors?per_page=50')
  expect(res.ok()).toBeTruthy()
  const body = (await res.json()) as { items?: Array<{ name: string; status: string }> }
  const target = (body.items ?? []).find((s) => s.status === 'active')
  test.skip(!target, 'Needs an active sensor')
  const name = page.getByText(target!.name, { exact: true }).locator('visible=true').first()
  await expect(name).toBeVisible({ timeout: 30_000 })
  await name.click()
  await expect(page.getByRole('dialog')).toBeVisible()
}

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
  test(
    `re-pair: reason, then a code for this sensor in the command, at ${width}px`,
    {
      tag: ['@sensors', '@serial'],
    },
    async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      await openFirstSensor(page)
      await page.getByRole('button', { name: 'More actions' }).click()
      const item = page.getByRole('menuitem', { name: 'Re-pair…' })
      test.skip((await item.count()) === 0, 'The signed-in user cannot pair sensors')
      await item.click()

      const dialog = page.getByTestId('repair-sensor-dialog')
      await expect(dialog).toBeVisible()
      const create = dialog.getByRole('button', { name: 'Create re-pair code' })
      // No reason, no code.
      await expect(create).toBeDisabled()
      await expect(dialog.getByRole('radio')).toHaveCount(4)

      // A compromised key ticks "Revoke the current key now" when it is offered.
      await dialog.getByText('Its key may be compromised').click()
      const revoke = dialog.getByRole('checkbox', { name: /Revoke the current key now/ })
      if ((await revoke.count()) > 0) {
        await expect(revoke).toBeChecked()
      }
      // Any other reason keeps the current key working until the approval.
      await dialog.getByText('Its identity is lost').click()
      if ((await revoke.count()) > 0) {
        await expect(revoke).not.toBeChecked()
      }
      await expect(dialog.getByText(/current key keeps working until you approve/)).toBeVisible()

      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
        width
      )
      expect(await seriousAxeIn(page, '[data-testid="repair-sensor-dialog"]')).toEqual([])

      await create.click()
      const code = dialog.locator('code').first()
      await expect(code).toHaveText(/^[0-9A-Z]{4}-[0-9A-Z]{4}$/, { timeout: 15_000 })
      const codeText = (await code.innerText()).trim()
      // The command carries the re-pair code and no API key.
      const snippet = dialog.locator('pre').first()
      await expect(snippet).toContainText(codeText)
      await expect(snippet).not.toContainText('SENSOR_API_KEY=')
      await expect(dialog.getByTestId('onboarding-status')).toBeVisible()
      await expect(
        dialog.getByText(/keeps working with its current key until you approve/)
      ).toBeVisible()

      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
        width
      )
      expect(await seriousAxeIn(page, '[data-testid="repair-sensor-dialog"]')).toEqual([])

      await dialog.getByRole('button', { name: 'Close' }).first().click()
      await expect(dialog).toBeHidden()
    }
  )
}
