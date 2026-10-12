import { test, expect } from '../fixtures/authenticated-page'
import { openFirstAssetSheet } from '../helpers/assets'
import { firstDataRow } from '../helpers/table'

/**
 * Critical Flow #2: Asset Relationships
 *
 * Verifies the asset inventory loads, the asset detail sheet has a Relations
 * tab, and its "Add relationship" dialog renders the type and target-asset
 * form. Locators use roles and accessible names, not layout or classes.
 */

test.describe('Asset relationship multi-select', () => {
  test('asset list page loads', async ({ page }) => {
    await page.goto('/assets')
    // The table renders, with rows or its empty state. Generous timeout:
    // asset queries can be slow on tenants with large inventories.
    await firstDataRow(page)
    await expect(page.getByRole('table').first()).toBeVisible()
  })

  test('opening an asset detail exposes a relationships section', async ({ page }) => {
    const sheet = await openFirstAssetSheet(page)
    test.skip(!sheet, 'No assets in tenant — seed at least one asset to run this test')
    await expect(sheet!.getByRole('tab', { name: 'Relations' })).toBeVisible()
  })

  test('add-relationship dialog renders its type + target form', async ({ page }) => {
    // The add-relationship dialog is a "relationship type → target asset" form
    // (pick a type, then the target-asset picker enables). The create itself
    // is not submitted, to keep the test side-effect free.
    const sheet = await openFirstAssetSheet(page)
    test.skip(!sheet, 'No assets in tenant — seed at least one asset to run this test')

    await sheet!.getByRole('tab', { name: 'Relations' }).click()
    await sheet!
      .getByRole('button', { name: /add relationship/i })
      .first()
      .click()

    // The add dialog is a second overlay on top of the sheet.
    const dialog = page.getByRole('dialog').last()
    await expect(dialog).not.toHaveAccessibleName(/details$/i)
    await expect(dialog.getByText(/relationship type/i).first()).toBeVisible()
    await expect(dialog.getByText(/target asset/i).first()).toBeVisible()
    await expect(dialog.getByRole('button', { name: /create/i }).first()).toBeVisible()

    // Cancel closes only the add dialog; the detail sheet stays open.
    await dialog
      .getByRole('button', { name: /cancel/i })
      .first()
      .click()
    await expect.poll(async () => page.getByRole('dialog').count(), { timeout: 5_000 }).toBe(1)
  })

  // TODO: happy-path — pick a relationship type, select a target asset, click
  // Create, and assert the Relations tab shows the new row. (The picker is now
  // a single type→target form, not a multi-select list; revisit whether batch
  // multi-target is still a product requirement before asserting it.)
})
