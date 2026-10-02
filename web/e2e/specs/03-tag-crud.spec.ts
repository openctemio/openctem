import { test, expect } from '../fixtures/authenticated-page'
import { openFirstAssetSheet } from '../helpers/assets'

/**
 * Critical Flow #3: Tag CRUD on Assets
 *
 * Tags are edited inline in the "Tags" section of the asset detail sheet:
 * "Edit tags" turns the chips into removable ones ("Remove tag <name>") plus
 * a text box, and "Save tags" writes them. The round trip reloads the sheet
 * so it checks what the API stored, not only local state.
 *
 * A unique tag name per run (`e2e-tag-<timestamp>`) avoids collisions with
 * concurrent runs.
 */

test.describe('Asset tag CRUD', () => {
  test('asset detail sheet exposes a tag input', async ({ page }) => {
    const sheet = await openFirstAssetSheet(page)
    test.skip(!sheet, 'No assets in tenant — seed at least one asset')

    const tags = sheet!.getByRole('region', { name: 'Tags' })
    await tags.getByRole('button', { name: 'Edit tags' }).click()
    await expect(tags.getByRole('textbox')).toBeVisible()
    await tags.getByRole('button', { name: 'Cancel' }).click()
    await expect(tags.getByRole('textbox')).toHaveCount(0)
  })

  test('add then remove a tag round-trips correctly', async ({ page }) => {
    const tagName = `e2e-tag-${Date.now()}`
    const sheet = await openFirstAssetSheet(page)
    test.skip(!sheet, 'No assets in tenant — seed at least one asset')
    const assetName = await sheet!.getByRole('heading', { level: 2 }).nth(1).innerText()

    const tags = () =>
      page.getByRole('dialog', { name: /details$/i }).getByRole('region', { name: 'Tags' })
    const reopen = async () => {
      await page.reload()
      await page.getByRole('row').filter({ hasText: assetName }).first().click()
      await expect(tags()).toBeVisible({ timeout: 15_000 })
    }

    // Add
    await tags().getByRole('button', { name: 'Edit tags' }).click()
    await tags().getByRole('textbox').fill(tagName)
    await tags().getByRole('textbox').press('Enter')
    await expect(tags().getByRole('button', { name: `Remove tag ${tagName}` })).toBeVisible()
    await tags().getByRole('button', { name: 'Save tags' }).click()
    await expect(tags().getByText(tagName, { exact: true })).toBeVisible({ timeout: 10_000 })

    await reopen()
    await expect(tags().getByText(tagName, { exact: true })).toBeVisible()

    // Remove
    await tags().getByRole('button', { name: 'Edit tags' }).click()
    await tags()
      .getByRole('button', { name: `Remove tag ${tagName}` })
      .click()
    await tags().getByRole('button', { name: 'Save tags' }).click()
    await expect(tags().getByText(tagName, { exact: true })).toHaveCount(0, { timeout: 10_000 })

    await reopen()
    await expect(tags().getByText(tagName, { exact: true })).toHaveCount(0)
  })
})
