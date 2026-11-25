import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { axeRuleViolations } from '../helpers/axe'

/**
 * Sensors list (research/354): the default columns fit 1440px with no
 * sideways scroll, each row is one line and says why it needs attention
 * beside its state (the seed's
 * e2e-sensor requires a local policy it does not have), the trust level New
 * reads "Passive only", and the row menu offers Revoke. At 390px the page
 * never scrolls sideways and the phone card gives the same reason.
 *
 * Read-only: nothing is clicked that changes a sensor.
 */

const rowFor = (page: Page, name: string) =>
  page.getByRole('row').filter({ has: page.getByText(name, { exact: true }) })

async function openSensors(page: Page) {
  await page.goto('/sensors')
  await expect(page.getByRole('heading', { name: 'Sensors', level: 1 })).toBeVisible()
}

test.describe('Sensors list', { tag: ['@sensors'] }, () => {
  test('1440px: the columns fit, the reason sits beside the state, Revoke in the menu', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 1000 })
    await openSensors(page)
    const row = rowFor(page, 'e2e-sensor')
    await expect(row).toBeVisible({ timeout: 30_000 })

    const headers = (await page.getByRole('columnheader').allInnerTexts())
      .map((h) => h.trim())
      .filter(Boolean)
    expect(headers).toEqual(['Sensor', 'Host', 'Status', 'Version', 'Jobs', 'Tools', 'Actions'])

    // The table's scroll box does not scroll sideways.
    const overflow = await page.getByRole('table').evaluate((table) => {
      const box = table.parentElement as HTMLElement
      return box.scrollWidth - box.clientWidth
    })
    expect(overflow).toBeLessThanOrEqual(1)

    await expect(row.locator('[data-slot="sensor-reason"]')).toHaveText(
      'No local policy: network tasks refused'
    )
    // One line per row at the default density.
    expect((await row.boundingBox())?.height).toBe(40)
    // A sensor still at trust level New (e2e-sensor-b) says what that means.
    await expect(rowFor(page, 'e2e-sensor-b').getByText('Passive only')).toBeVisible()

    await row.getByRole('button', { name: /Actions for e2e-sensor/ }).click()
    await expect(page.getByRole('menuitem', { name: 'Revoke', exact: true })).toBeVisible()
    await page.keyboard.press('Escape')
    // The menu fades out for a moment: axe reads the colours of a half
    // transparent menu as low contrast, so check once it is gone.
    await expect(page.getByRole('menu')).toBeHidden()

    expect(await axeRuleViolations(page, ['color-contrast', 'aria-allowed-attr'])).toEqual([])
  })

  test('390px: no sideways scroll, the card gives the same reason', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await openSensors(page)
    const card = page
      .locator('[data-slot="sensor-card"]')
      .filter({ hasText: 'e2e-sensor' })
      .filter({
        hasText: 'No local policy: network tasks refused',
      })
    await expect(card.first()).toBeVisible({ timeout: 30_000 })
    const sideways = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth
    )
    expect(sideways).toBeLessThanOrEqual(0)
  })
})
