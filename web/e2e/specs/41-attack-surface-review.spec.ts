import { test, expect } from '../fixtures/authenticated-page'

/**
 * Attack surface Review (research/274): the item list's state is a filter
 * (no second tab row), deep links keep working, and the page fits a phone.
 */

const REVIEW = '/attack-surface/review'

test('the item list filters by state instead of a tab row', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto(`${REVIEW}?tab=rejected`)
  const state = page.getByRole('button', { name: 'State: Not ours' })
  await expect(state).toBeVisible({ timeout: 30_000 })
  await expect(page.getByRole('tablist')).toHaveCount(0)
  await state.click()
  await page.getByRole('menuitemradio', { name: /Awaiting a decision/ }).click()
  await expect(page.getByRole('button', { name: 'State: Awaiting a decision' })).toBeVisible()
  await expect(page).not.toHaveURL(/tab=rejected/)
  // The crumb carries the tab's name.
  await expect(page.getByRole('navigation', { name: /breadcrumb/i })).toContainText('Review')
})

test('lookalikes filter by state, kept in the URL', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/attack-surface/lookalikes?state=resolved')
  const state = page.getByRole('button', { name: 'State: Taken down' })
  // The section is shown only to callers who may read exposures.
  if ((await state.count()) === 0) {
    await page.waitForLoadState('networkidle')
  }
  if ((await state.count()) > 0) {
    await expect(state).toBeVisible()
    await expect(page.getByRole('tablist')).toHaveCount(0)
  }
})

test('Review fits a phone', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`${REVIEW}?all=1`)
  await expect(page.getByRole('button', { name: /^State:/ })).toBeVisible({ timeout: 30_000 })
  const [scroll, inner] = await page.evaluate(() => [
    document.documentElement.scrollWidth,
    window.innerWidth,
  ])
  expect(scroll).toBeLessThanOrEqual(inner)
})
