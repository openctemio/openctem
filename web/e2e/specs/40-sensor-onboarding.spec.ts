import path from 'path'
import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Add sensor (research/280, 356): one panel, inline on the empty Sensors page
 * and in the Add sensor dialog, and one path: the dialog opens on one command
 * that carries a single-use code (no API key, no policy file, a watch that
 * ends on "Paired:"), the platform tabs switch the command, the status shows
 * "waiting for the sensor"; the approve page a sensor's link opens reads the
 * code, removes it from the address and answers a code nobody holds with the
 * uniform "not found". Both fit a phone with no sideways scroll and no
 * serious or critical accessibility violation. With a private platform CA the
 * panel names it, shows the pinned root's SHA-256 and the download, and the
 * multi-sensor kit's command carries the pin. The opened dialog leaves an
 * expectation that expires on its own in 10 minutes; nothing else changes.
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
    `one path: the dialog opens on one command with its code, at ${width}px`,
    { tag: ['@sensors'] },
    async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      const panel = await openPanel(page)
      await expect(panel.getByTestId('sensor-onboarding')).toBeVisible()
      // The inline empty state waits for a click; the dialog shows the
      // command at once.
      const show = panel.getByRole('button', { name: 'Show the command' })
      if (await show.isVisible()) await show.click()

      const command = panel.locator('pre[data-format]').first()
      await expect(command).toContainText('SENSOR_PAIRING_CODE=', { timeout: 15_000 })
      await expect(command).toContainText('--cap-drop ALL')
      await expect(command).toContainText('Paired:*|Enrolled:*) break')
      await expect(command).not.toContainText('SENSOR_API_KEY')
      await expect(command).not.toContainText('SENSOR_LOCAL_POLICY')
      await expect(panel.getByTestId('onboarding-status')).toContainText('Waiting for the sensor')
      // No choice of flow, no code box in the dialog.
      await expect(panel.getByText('How should it join?')).toHaveCount(0)
      await expect(panel.getByRole('textbox', { name: 'Pairing code' })).toHaveCount(0)
      await expect(panel.getByRole('link', { name: /open the approve page/i })).toHaveAttribute(
        'href',
        '/activate'
      )

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

  test(
    `a private platform CA: every command pins its root, at ${width}px`,
    { tag: ['@sensors'] },
    async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      // The e2e stack has a public certificate; give the real answer the
      // platform_ca an API with PLATFORM_CA_CERT_FILE sends.
      const root = 'ab'.repeat(32)
      await page.route('**/api/v1/sensors/install-templates', async (route) => {
        const response = await route.fetch()
        const body = await response.json()
        await route.fulfill({
          response,
          json: {
            ...body,
            docker: `${body.docker}\n# SENSOR_CA_SHA256=${root}`,
            multi: `./sensors.sh add 'openctem-sensor' --api-url 'https://ctem.example.test' --ca-sha256 ${root}`,
            platform_ca: {
              pin: root,
              download_path: '/api/v1/sensors/platform-ca',
              certificates: [
                {
                  common_name: 'OpenCTEM Internal CA - ECC Intermediate',
                  sha256: 'CD:'.repeat(31) + 'CD',
                  sha256_hex: 'cd'.repeat(32),
                  root: false,
                  not_after: '2036-08-09T14:58:23Z',
                },
                {
                  common_name: 'OpenCTEM Internal CA - 2026 ECC Root',
                  sha256: 'AB:'.repeat(31) + 'AB',
                  sha256_hex: root,
                  root: true,
                  not_after: '2036-08-09T14:58:23Z',
                },
              ],
            },
          },
        })
      })
      const panel = await openPanel(page)
      const show = panel.getByRole('button', { name: 'Show the command' })
      if (await show.isVisible()) await show.click()

      const ca = panel.getByTestId('platform-ca')
      await expect(ca).toBeVisible({ timeout: 15_000 })
      await expect(ca).toContainText('OpenCTEM Internal CA - 2026 ECC Root')
      await expect(ca).toContainText('AB:'.repeat(31) + 'AB')
      await expect(ca).toContainText('SENSOR_CA_SHA256')
      await expect(ca.getByRole('link', { name: 'Download CA certificates' })).toHaveAttribute(
        'href',
        '/api/v1/sensors/platform-ca'
      )
      await panel.getByRole('radio', { name: 'Several on one host' }).click()
      await expect(panel.locator('pre[data-format]').first()).toContainText(`--ca-sha256 ${root}`)

      const sideways = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth
      )
      expect(sideways).toBeLessThanOrEqual(0)
      const sel = (await page.getByRole('dialog').count()) > 0 ? '[role=dialog]' : 'main#content'
      expect(await seriousAxeIn(page, sel)).toEqual([])
    }
  )

  test(
    `the approve page takes the link's code and removes it from the address, at ${width}px`,
    { tag: ['@sensors'] },
    async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      // A well-formed code nobody holds: the uniform "not found".
      await page.goto('/activate?code=ZZZZ-ZZZZ')
      const card = page.getByTestId('activate-sensor')
      await expect(card).toBeVisible({ timeout: 30_000 })
      await expect(page).toHaveURL(/\/activate$/)
      await expect(card.getByRole('alert')).toContainText('Code not found or expired', {
        timeout: 15_000,
      })
      await expect(card.getByTestId('pairing-phishing-warning')).toBeVisible()
      const sideways = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth
      )
      expect(sideways).toBeLessThanOrEqual(0)
      expect(await seriousAxeIn(page, '[data-testid="activate-sensor"]')).toEqual([])
    }
  )
}
