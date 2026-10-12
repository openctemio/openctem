import type { Locator, Page } from '@playwright/test'

/**
 * Data rows of the page's tables: rows with at least two cells. The header
 * row has column headers, not cells, and an empty table renders a single
 * full-width "No ... yet" cell, so neither is matched. `getByRole('row').nth(1)`
 * picked that empty-state row and made "skip when there is no data" checks
 * click it and fail instead.
 */
export function dataRows(scope: Page | Locator): Locator {
  return scope.getByRole('row').filter({ has: scope.getByRole('cell').nth(1) })
}

/** The first data row, or null when the table is empty (after it has loaded). */
export async function firstDataRow(page: Page): Promise<Locator | null> {
  await page.getByRole('table').first().waitFor({ state: 'visible', timeout: 30_000 })
  await page.waitForLoadState('networkidle')
  const row = dataRows(page).first()
  return (await row.isVisible().catch(() => false)) ? row : null
}
