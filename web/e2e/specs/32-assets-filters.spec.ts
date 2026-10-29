import { test, expect } from '../fixtures/authenticated-page'

/**
 * Asset filters: Add filter lists the facets, a picked facet applies as you
 * tick and shows as a chip, the chip removes it, and the page asks for no
 * tag list or business units until something shows them.
 */

test.describe('Asset filters', { tag: ['@assets'] }, () => {
  test('Add filter applies a facet as a chip, and the chip removes it', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/assets')
    await expect(page.getByTestId('inventory-filter-bar')).toBeVisible({ timeout: 20_000 })
    await page.getByRole('button', { name: /add filter/i }).click()
    await page.getByRole('option', { name: 'Criticality' }).click()
    await page.getByRole('checkbox', { name: 'Critical' }).click()
    await expect(page).toHaveURL(/criticalities=critical/)
    await page.getByRole('button', { name: 'Done' }).click()
    const chip = page
      .getByTestId('inventory-filter-chip')
      .filter({ hasText: 'Criticality is Critical' })
    await expect(chip).toBeVisible()
    await chip.getByRole('button', { name: /remove filter/i }).click()
    await expect(page).not.toHaveURL(/criticalities=/)
  })

  test('a cold load asks for no tag list and no business units', async ({ page }) => {
    const asked: string[] = []
    page.on('request', (r) => {
      const u = new URL(r.url())
      if (/\/api\/v1\/(business-units|assets\/tags\?include_system)/.test(u.pathname + u.search))
        asked.push(u.pathname + u.search)
    })
    await page.goto('/assets')
    await expect(page.getByTestId('inventory-filter-bar')).toBeVisible({ timeout: 20_000 })
    await page.waitForLoadState('networkidle')
    expect(asked).toEqual([])
  })
})
