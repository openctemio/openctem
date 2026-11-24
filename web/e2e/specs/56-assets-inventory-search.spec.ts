import { test, expect } from '../fixtures/authenticated-page'

/**
 * The asset inventory on the shared search box: inside the External surface
 * lens the type is a "Type" filter token at the start of the toolbar (a locked
 * condition, not a second tab row), the Query toggle edits the same
 * filter as text, and a text that chips can show lands in the URL as flat
 * params. Needs the API with the list query contract (GET /assets takes the
 * registry's names, POST /query/parse knows the assets entity).
 */

test.describe('Asset inventory search', { tag: ['@assets'] }, () => {
  test('the External surface lens has a type token, and a type is a locked condition', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/assets?lens=external_surface')
    const type = page.getByRole('button', { name: /^Type: / })
    await expect(type).toBeVisible({ timeout: 20_000 })
    await expect(page.locator('main [data-testid="segmented-lens"]')).toHaveCount(0)
    await type.click()
    await page.getByRole('menuitemradio', { name: /IP addresses/ }).click()
    await expect(page).toHaveURL(/tab=ip_address/)
    await expect(page).not.toHaveURL(/types=/)
    await expect(page.getByTestId('inventory-view-title')).toHaveText(/IP addresses/i)
  })

  test('an old single-type link opens the matching type', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/assets?lens=external_surface&types=subdomain')
    await expect(page.getByRole('button', { name: 'Type: Subdomains' })).toBeVisible({
      timeout: 20_000,
    })
  })

  test('other lenses keep the type facet and show no type token', async ({ page }) => {
    await page.goto('/assets?lens=code')
    // The list has loaded: its count shows in the title row (no chips row without a filter).
    await expect(page.locator('main [data-slot="list-count"]')).toHaveText(/\d/, {
      timeout: 20_000,
    })
    await expect(page.getByRole('button', { name: /^Type: / })).toHaveCount(0)
  })

  test('Query mode of the search field edits the filter as text, written back as flat params', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/assets?lens=external_surface&tab=ip_address')
    // The list has loaded: its count shows in the title row (no chips row without a filter).
    await expect(page.locator('main [data-slot="list-count"]')).toHaveText(/\d/, {
      timeout: 20_000,
    })
    await page.getByRole('button', { name: /^query$/i }).click()
    const box = page.getByRole('combobox', { name: /filter as query text/i })
    await expect(box).toBeEnabled()
    await box.fill('port>=1')
    await box.press('Enter')
    await expect(page).toHaveURL(/port_gte=1/)
    await expect(page).toHaveURL(/tab=ip_address/)
    // The field stays in Query mode; back in Basic the same filter is a chip.
    await expect(box).toHaveValue(/port>=1/)
    await page.getByRole('button', { name: /^basic$/i }).click()
    await expect(page.getByTestId('inventory-filter-chip').first()).toContainText(/port/i)
  })
})
