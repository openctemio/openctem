import { test, expect } from '../fixtures/authenticated-page'
import { layoutDefects, seriousAxe } from '../helpers/layout'

/**
 * Settings > Modules (research/394 §4): every group open, dependencies written
 * out by name, a preview before a save that turns modules off (dependents
 * listed, turned off together), search, no sideways scroll on a phone and no
 * serious accessibility violation in light and dark. Nothing is saved: the
 * preview is cancelled and the change discarded, so other specs see the
 * seeded state.
 */
for (const scheme of ['light', 'dark'] as const) {
  test(`modules page at 1440px in ${scheme}`, { tag: ['@settings'] }, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/settings/modules')
    await expect(page.getByRole('heading', { name: 'Scoping' })).toBeVisible()
    await page.waitForLoadState('networkidle')

    // Groups start open and dependencies are text, not tooltips.
    const cycles = page.locator('[data-module="ctem_cycles"]')
    await expect(cycles).toContainText('Requires Scope')
    await expect(page.locator('[data-module="scope_config"]')).toContainText(
      'Required by CTEM cycles'
    )
    expect(await seriousAxe(page)).toEqual([])

    // Turning Scope off previews CTEM cycles going with it; cancel and discard.
    await page.getByRole('switch', { name: 'Scope', exact: true }).click()
    await expect(cycles).toContainText('Turns off with Scope')
    await page.getByRole('button', { name: /^Save/ }).click()
    const dialog = page.getByRole('alertdialog')
    await expect(dialog).toContainText('Also turning off, because they need it')
    await expect(dialog).toContainText('CTEM cycles')
    await expect(dialog.getByRole('button', { name: /^Turn off all \d+ together$/ })).toBeVisible()
    await dialog.getByRole('button', { name: 'Cancel' }).click()
    await page.getByRole('button', { name: 'Discard' }).click()
    await expect(page.getByRole('switch', { name: 'Scope', exact: true })).toBeChecked()

    // Search narrows the list to matching modules.
    await page.getByRole('searchbox', { name: 'Search modules' }).fill('penetration')
    await expect(page.locator('[data-module="pentest"]')).toBeVisible()
    await expect(page.locator('[data-module="scope_config"]')).toHaveCount(0)
  })
}

test('modules page at 390px: no sideways scroll', { tag: ['@settings'] }, async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/settings/modules')
  await expect(page.getByRole('heading', { name: 'Scoping' })).toBeVisible()
  await page.waitForLoadState('networkidle')
  expect(await layoutDefects(page)).toEqual([])
  expect(await seriousAxe(page)).toEqual([])
})
