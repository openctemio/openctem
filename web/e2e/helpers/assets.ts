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
  // The sheet is a dialog named after the asset type ("Domain details", ...).
  const sheet = page.getByRole('dialog', { name: /details$/i })
  await expect(sheet).toBeVisible({ timeout: 15_000 })
  return sheet
}
