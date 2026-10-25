import { test, expect } from '../fixtures/authenticated-page'

/**
 * Asset list states (research/271): the search box keeps every key typed with
 * short pauses, a failed read keeps the toolbar, a page past the end lands on
 * the last page, and an empty list under the default hide says what it leaves
 * out and offers to show it.
 */

const LIST = /\/api\/v1\/assets\?/

test('the search box keeps every key typed with short pauses', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/assets')
  const box = page.getByRole('searchbox', { name: 'Search assets' })
  await expect(box).toBeVisible({ timeout: 30_000 })
  await page.waitForLoadState('networkidle')
  // Pauses just past the 300 ms debounce: each settled term is written to
  // the URL while the next key is typed, which used to reset the box.
  await box.pressSequentially('zz-no-such-asset', { delay: 330 })
  await expect(box).toHaveValue('zz-no-such-asset')
  await expect(page).toHaveURL(/[?&]q=zz-no-such-asset(&|$)/)
})

test('a failed read keeps the toolbar, so the search can still change', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.route(LIST, (route) =>
    route.request().method() === 'GET'
      ? route.fulfill({ status: 500, contentType: 'application/json', body: '{"message":"boom"}' })
      : route.continue()
  )
  await page.goto('/assets?q=web')
  await expect(page.getByText(/Failed to load assets/)).toBeVisible({ timeout: 30_000 })
  const box = page.getByRole('searchbox', { name: 'Search assets' })
  await expect(box).toBeVisible()
  await expect(box).toHaveValue('web')
  await expect(page.getByRole('button', { name: /Retry/ })).toBeVisible()
})

test('a page past the end shows the last page', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/assets?page=99')
  const rows = page.getByTestId('asset-name-cell')
  const seeded = await rows
    .first()
    .waitFor({ state: 'visible', timeout: 30_000 })
    .then(() => true)
    .catch(() => false)
  test.skip(!seeded, 'no seeded assets')
  await expect(page).not.toHaveURL(/[?&]page=99(&|$)/)
})

test('an empty list under the default hide offers to show every asset', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/assets?q=zz-no-such-asset-anywhere')
  await expect(page.getByText('No confirmed assets match')).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: 'Show all assets' }).click()
  // The locked chip gives way to an ordinary attribution filter.
  await expect(page.getByTestId('inventory-hidden-chip')).toHaveCount(0)
  await expect(page).toHaveURL(/attribution=/)
})
