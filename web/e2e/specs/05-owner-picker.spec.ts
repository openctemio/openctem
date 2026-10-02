import { test, expect } from '../fixtures/authenticated-page'
import { openFirstAssetSheet } from '../helpers/assets'

/**
 * Critical Flow #5: Owner Picker
 *
 * Verifies the asset owner picker on the asset detail sheet: the Owners tab
 * lists the owners, and "Add Owner" opens a dialog whose owner picker offers
 * at least one user or group (the seed user themselves). Nothing is saved.
 */

test.describe('Asset owner picker', () => {
  test('owner field is present on the asset detail sheet', async ({ page }) => {
    const sheet = await openFirstAssetSheet(page)
    test.skip(!sheet, 'No assets in tenant — seed at least one asset')

    await expect(sheet!.getByRole('region', { name: 'Ownership' })).toBeVisible()
    await sheet!.getByRole('tab', { name: 'Owners' }).click()
    await expect(sheet!.getByRole('heading', { name: /^Owners \(\d+\)$/ })).toBeVisible()
  })

  test('owner picker opens and shows at least one candidate', async ({ page }) => {
    const sheet = await openFirstAssetSheet(page)
    test.skip(!sheet, 'No assets in tenant — seed at least one asset')

    await sheet!.getByRole('tab', { name: 'Owners' }).click()
    await sheet!.getByRole('button', { name: 'Add Owner' }).first().click()

    const dialog = page.getByRole('dialog', { name: 'Add Owner' })
    await expect(dialog).toBeVisible()
    await dialog.getByRole('combobox').first().click()

    // The candidate list (users and groups) has at least the seed user.
    await expect(page.getByRole('option').first()).toBeVisible({ timeout: 10_000 })

    await page.keyboard.press('Escape')
    await dialog.getByRole('button', { name: 'Cancel' }).click()
    await expect(dialog).toBeHidden()
  })
})
