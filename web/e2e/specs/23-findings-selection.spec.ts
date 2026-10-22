import { test, expect } from '../fixtures/authenticated-page'

/**
 * Findings list selection. A selection belongs to the rows on screen, so a
 * page, search, sort or filter change clears it; and a phone shows the same
 * checkbox and menu a table row has. Skips when the stack has no findings.
 */

const bulkBar = (page: import('@playwright/test').Page) =>
  page.getByRole('toolbar', { name: /actions for selected rows/i })

test.describe('Findings selection', () => {
  test('a search change clears the selection', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 })
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')
    const box = page.getByRole('checkbox', { name: /select finding/i }).first()
    test.skip(!(await box.isVisible().catch(() => false)), 'No selectable findings on this stack')

    await box.check()
    await expect(bulkBar(page)).toBeVisible()

    await page.getByRole('textbox', { name: /search findings/i }).fill('zz-no-such-finding')
    await expect(bulkBar(page)).toBeHidden({ timeout: 10_000 })
  })

  test('a sort change clears the selection', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 })
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')
    const box = page.getByRole('checkbox', { name: /select finding/i }).first()
    test.skip(!(await box.isVisible().catch(() => false)), 'No selectable findings on this stack')

    await box.check()
    await expect(bulkBar(page)).toBeVisible()
    // The header's sort menu: Status, ascending.
    await page
      .getByRole('columnheader', { name: /^status/i })
      .getByRole('button')
      .click()
    await page.getByRole('menuitem', { name: 'Asc' }).click()
    await expect(bulkBar(page)).toBeHidden({ timeout: 10_000 })
  })

  test('a phone card has a checkbox and a menu', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')
    const card = page.getByTestId('finding-phone-card').first()
    test.skip(!(await card.isVisible().catch(() => false)), 'No findings on this stack')

    const box = card.getByRole('checkbox')
    await box.check()
    await expect(bulkBar(page)).toBeVisible()
    await card.getByRole('button', { name: /actions for/i }).click()
    await expect(page.getByRole('menuitem', { name: /view details/i })).toBeVisible()
    // No page-level horizontal scroll at phone width.
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth
    )
    expect(overflow).toBe(false)
  })
})
