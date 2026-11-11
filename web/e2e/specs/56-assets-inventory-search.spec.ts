import { test, expect } from '../fixtures/authenticated-page'

/**
 * The asset inventory on the shared search box: inside the External surface
 * lens the type is a tab (a locked condition), the Query toggle edits the same
 * filter as text, and a text that chips can show lands in the URL as flat
 * params. Needs the API with the list query contract (GET /assets takes the
 * registry's names, POST /query/parse knows the assets entity).
 */

test.describe('Asset inventory search', { tag: ['@assets'] }, () => {
  test('the External surface lens has type tabs, and a tab is a locked type', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/assets?lens=external_surface')
    const tabs = page.getByRole('radiogroup', { name: /asset type/i })
    await expect(tabs).toBeVisible({ timeout: 20_000 })
    await tabs.getByRole('radio', { name: /IP addresses/ }).click()
    await expect(page).toHaveURL(/tab=ip_address/)
    await expect(page).not.toHaveURL(/types=/)
    await expect(page.getByTestId('inventory-view-title')).toHaveText(/IP addresses/i)
  })

  test('an old single-type link opens the matching tab', async ({ page }) => {
    await page.goto('/assets?lens=external_surface&types=subdomain')
    await expect(page.getByRole('radio', { name: /Subdomains/, checked: true })).toBeVisible({
      timeout: 20_000,
    })
  })

  test('other lenses keep the type facet and show no tabs', async ({ page }) => {
    await page.goto('/assets?lens=code')
    await expect(page.getByTestId('inventory-filter-bar')).toBeVisible({ timeout: 20_000 })
    await expect(page.getByRole('radiogroup', { name: /asset type/i })).toHaveCount(0)
  })

  test('the Query toggle edits the filter as text, written back as flat params', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/assets?lens=external_surface&tab=ip_address')
    await expect(page.getByTestId('inventory-filter-bar')).toBeVisible({ timeout: 20_000 })
    await page.getByRole('button', { name: /^query$/i }).click()
    const box = page.getByRole('combobox', { name: /filter as query text/i })
    await expect(box).toBeEnabled()
    await box.fill('port>=1')
    await box.press('Enter')
    await expect(page).toHaveURL(/port_gte=1/)
    await expect(page).toHaveURL(/tab=ip_address/)
    await expect(page.getByTestId('inventory-filter-chip').first()).toContainText(/port/i)
  })
})
