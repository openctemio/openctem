import { test, expect } from '../fixtures/authenticated-page'

/**
 * Asset quick views: while the inventory is open, the sidebar lists All
 * assets and the lenses that hold an asset under Assets, each a plain link
 * to the list with `?lens=`; the list names the open view, and the old lens
 * pills, type pills and metric strip are gone.
 */

test.describe('Asset quick views', () => {
  test('the sidebar lists the views under Assets, and a view is a link to the list', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/assets')
    const nav = page.getByRole('list', { name: /asset views/i })
    await expect(nav).toBeVisible({ timeout: 20_000 })
    const all = nav.getByRole('link', { name: /^All assets/ })
    await expect(all).toHaveAttribute('href', '/assets')
    await expect(all).toHaveAttribute('aria-current', 'page')
    await expect(page.getByTestId('inventory-view-title')).toHaveText('All assets')
    const lenses = nav.getByRole('link').filter({ hasNot: page.getByText(/^All assets/) })
    if ((await lenses.count()) > 0) {
      const first = lenses.first()
      const href = await first.getAttribute('href')
      await first.click()
      await expect(page).toHaveURL(new RegExp(href!.replace('?', '\\?')))
      await expect(first).toHaveAttribute('aria-current', 'page')
    }
  })

  test('the list has no lens pills, no type pills and no metric strip', async ({ page }) => {
    await page.goto('/assets')
    await expect(page.getByTestId('inventory-view-title')).toBeVisible({ timeout: 20_000 })
    await expect(page.getByRole('toolbar', { name: /asset lens/i })).toHaveCount(0)
    await expect(page.locator('[data-slot="inventory-lens-bar"]')).toHaveCount(0)
    await expect(page.getByText('High risk', { exact: true })).toHaveCount(0)
  })

  test('the views are not listed on other pages', async ({ page }) => {
    await page.goto('/assets/groups')
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('list', { name: /asset views/i })).toHaveCount(0)
  })
})
