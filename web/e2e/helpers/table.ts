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

/**
 * Phone, on the findings list: select mode is the first item of the list's
 * More in the title row (a small menu or a bottom sheet, by fit); the toolbar
 * has no More of its own.
 */
export async function openFindingsPhoneSelect(page: Page): Promise<void> {
  await page
    .getByTestId('findings-toolbar-primary')
    .getByRole('button', { name: /more actions|thao tác khác/i })
    .filter({ visible: true })
    .click()
  await page
    .locator('[role="menuitem"], [role="menuitemcheckbox"], [data-slot="action-sheet-row"]')
    .filter({ visible: true })
    .first()
    .click()
}
