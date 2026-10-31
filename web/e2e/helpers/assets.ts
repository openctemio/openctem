import type { Locator, Page } from '@playwright/test'
import { expect } from '@playwright/test'
import { firstDataRow } from './table'

/**
 * Opens the detail sheet of the first asset in the inventory (/assets lists
 * every type, so any seeded asset works). Returns the sheet, or null when
 * the tenant has no assets.
 */
export async function openFirstAssetSheet(page: Page): Promise<Locator | null> {
  await page.goto('/assets')
  const row = await firstDataRow(page)
  if (!row) return null
  await clickPlainCell(row)
  // The drawer is the only dialog; its accessible name is the asset's name.
  const sheet = page.getByRole('dialog')
  await expect(sheet).toBeVisible({ timeout: 15_000 })
  return sheet
}

/**
 * Clicks a cell of the row that holds no link, button or checkbox. The middle
 * of a row can land on the inline monitoring menu or another control, which
 * handles its own click instead of opening the row's drawer.
 */
async function clickPlainCell(row: Locator): Promise<void> {
  const cells = row.getByRole('cell')
  const count = await cells.count()
  for (let i = 0; i < count; i++) {
    const cell = cells.nth(i)
    const interactive = await cell.locator('a, button, input, [role="checkbox"]').count()
    if (interactive === 0 && (await cell.isVisible())) {
      await cell.click()
      return
    }
  }
  await row.click()
}
