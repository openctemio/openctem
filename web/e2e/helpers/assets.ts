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
  await row.click()
  // The drawer is the only dialog; its accessible name is the asset's name.
  const sheet = page.getByRole('dialog')
  await expect(sheet).toBeVisible({ timeout: 15_000 })
  return sheet
}
