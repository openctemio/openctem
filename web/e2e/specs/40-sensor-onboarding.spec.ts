import path from 'path'
import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Add sensor (research/280): one panel, inline on the empty Sensors page and
 * in the Add sensor dialog. Creating a pairing code puts it into the exact
 * install command (no API key anywhere), the platform tabs switch the
 * command, the status shows "waiting for the sensor", and the panel fits a
 * phone with no sideways scroll and no serious or critical accessibility
 * violation. Creating a code leaves an expectation that expires on its own
 * in 10 minutes; nothing else is changed.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

async function openPanel(page: Page): Promise<Locator> {
  await page.goto('/sensors')
  await expect(page.getByRole('heading', { name: 'Sensors', level: 1 })).toBeVisible()
  const add = page.getByRole('button', { name: 'Add sensor' })
  const inline = page.getByTestId('sensor-onboarding')
  await expect(add.or(inline).first()).toBeVisible({ timeout: 30_000 })
  if (await add.isVisible()) {
    await add.click()
    return page.getByRole('dialog')
  }
  return page.locator('main#content')
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
    `create a code first: the command carries it, at ${width}px`,
    { tag: ['@sensors'] },
    async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      const panel = await openPanel(page)
      await expect(panel.getByTestId('sensor-onboarding')).toBeVisible()

      await panel.getByRole('button', { name: 'Create pairing code' }).click()
      const command = panel.locator('pre[data-format]').first()
      await expect(command).toContainText('SENSOR_PAIRING_CODE=', { timeout: 15_000 })
      await expect(command).toContainText('--cap-drop ALL')
      await expect(command).not.toContainText('SENSOR_API_KEY')
      await expect(panel.getByTestId('onboarding-status')).toContainText('Waiting for the sensor')

      await panel.getByRole('radio', { name: 'Linux service' }).click()
      await expect(command).toContainText('systemctl enable --now openctem-sensor')
      await panel.getByRole('radio', { name: 'Kubernetes' }).click()
      await expect(command).toContainText('kind: Deployment')

      const sideways = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth
      )
      expect(sideways).toBeLessThanOrEqual(0)
      const sel = (await page.getByRole('dialog').count()) > 0 ? '[role=dialog]' : 'main#content'
      expect(await seriousAxeIn(page, sel)).toEqual([])
    }
  )
}

test(
  'pair interactively: the command has no code and the code entry follows',
  { tag: ['@sensors'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    const panel = await openPanel(page)
    await panel.getByText('Pair a sensor that shows a code').click()
    const command = panel.locator('pre[data-format]').first()
    await expect(command).toContainText('docker run', { timeout: 15_000 })
    await expect(command).not.toContainText('SENSOR_PAIRING_CODE')
    await expect(panel.getByRole('textbox', { name: 'Pairing code' })).toBeVisible()
  }
)
