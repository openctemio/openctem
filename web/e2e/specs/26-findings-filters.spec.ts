import { test, expect } from '../fixtures/authenticated-page'

/**
 * Findings filters: every active filter is a chip, Add filter is built from the
 * API's filter contract (searchable, grouped, typed), an unknown filter in a
 * shared link is named and removable, and a filter the page does not draw
 * itself still reaches the API. Needs no particular data.
 */

test.describe('Findings filters', { tag: ['@findings'] }, () => {
  test('Add filter lists the contract fields, searches them and adds a chip and a URL param', async ({
    page,
  }) => {
    await page.goto('/findings')
    await page.getByRole('button', { name: /add filter/i }).click()
    const dialog = page.getByRole('dialog', { name: /add filter/i })
    await expect(dialog.getByRole('option', { name: 'Severity' })).toBeVisible({ timeout: 20_000 })
    for (const group of ['Exploitation', 'Finding']) {
      await expect(dialog.getByText(group, { exact: true })).toBeVisible()
    }
    await dialog.getByPlaceholder(/search fields/i).fill('epss')
    await expect(dialog.getByRole('option', { name: 'Severity' })).toHaveCount(0)
    await dialog.getByRole('option', { name: /epss score/i }).click()
    await dialog.getByLabel('Value').fill('0.5')
    await dialog.getByRole('button', { name: 'Apply' }).click()
    await expect(page).toHaveURL(/epss_score_gte=0\.5/)
    await expect(
      page.getByTestId('filter-chip').filter({ hasText: 'EPSS score ≥ 0.5' })
    ).toBeVisible()
  })

  test('the f key opens Add filter, not while typing in search', async ({ page }) => {
    await page.goto('/findings')
    const search = page.getByRole('searchbox', { name: /search findings/i })
    await search.click()
    await page.keyboard.type('f')
    await expect(page.getByRole('dialog', { name: /add filter/i })).toHaveCount(0)
    await search.fill('')
    await page.locator('h1').click()
    await page.keyboard.press('f')
    await expect(page.getByRole('dialog', { name: /add filter/i })).toBeVisible()
  })

  test('a facet filter shows as a chip and removes from the URL', async ({ page }) => {
    await page.goto('/findings?severity=critical')
    const chip = page.getByTestId('filter-chip').filter({ hasText: 'Severity is Critical' })
    await expect(chip).toBeVisible({ timeout: 20_000 })
    await chip.getByRole('button', { name: /remove filter/i }).click()
    await expect(page).not.toHaveURL(/severity=/)
  })

  test('an unknown filter in a link is named, and removable', async ({ page }) => {
    await page.goto('/findings?sevrity=high')
    await expect(
      page.getByTestId('invalid-filter-notice').or(page.getByTestId('filter-chip-unknown'))
    ).toBeVisible({
      timeout: 20_000,
    })
    await expect(page.getByText(/sevrity/).first()).toBeVisible()
    const remove = page
      .getByRole('button', { name: /remove it/i })
      .or(page.getByRole('button', { name: /remove unknown filter/i }))
    await remove.first().click()
    await expect(page).not.toHaveURL(/sevrity=/)
  })

  test('a filter the page does not draw itself reaches the list request', async ({ page }) => {
    const seen: string[] = []
    page.on('request', (r) => {
      const u = new URL(r.url())
      if (u.pathname === '/api/v1/findings') seen.push(u.search)
    })
    await page.goto('/findings?epss_score_gte=0.5')
    await expect(page.getByTestId('filter-chip').filter({ hasText: 'EPSS score' })).toBeVisible({
      timeout: 20_000,
    })
    expect(seen.some((q) => q.includes('epss_score_gte=0.5'))).toBe(true)
  })

  test('a plain list does not ask for the filter contract', async ({ page }) => {
    const asked: string[] = []
    page.on('request', (r) => {
      if (r.url().includes('/api/v1/meta/filters/findings')) asked.push(r.url())
    })
    await page.goto('/findings?severity=high')
    await page.waitForLoadState('networkidle')
    expect(asked).toEqual([])
  })
})
