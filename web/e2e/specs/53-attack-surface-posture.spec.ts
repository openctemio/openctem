import { test, expect } from '../fixtures/authenticated-page'

/**
 * Attack surface > Posture (server/docs/architecture/easm-posture.md): the view
 * opens the page, the page shows a grade or why there is none, and the
 * overview card links to it.
 */

const POSTURE = '/attack-surface/posture'

test('the Posture tab opens a graded page', { tag: ['@attack-surface'] }, async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/attack-surface')
  const tabs = page.getByRole('navigation', { name: 'Attack surface sections' })
  await expect(tabs).toBeVisible({ timeout: 30_000 })
  await expect(page.getByTestId('posture-card')).toBeVisible()
  // Posture is a view of the Overview tab.
  await page
    .getByRole('radiogroup', { name: 'Overview views' })
    .getByRole('radio', { name: 'Posture' })
    .click()
  await expect(page).toHaveURL(new RegExp(`${POSTURE}$`))
  await page.waitForLoadState('networkidle')
  // Either a grade, or the reason there is none yet.
  await expect(
    page
      .getByRole('img', { name: /^Grade [ABCDF], score \d+ of 100$/ })
      .or(page.getByText(/first posture computation is running|No surface asset in your view/))
      .first()
  ).toBeVisible()
  await expect(page.getByText('How the score is computed')).toBeVisible()
})

test('the posture page fits a phone', { tag: ['@attack-surface'] }, async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(POSTURE)
  await page.waitForLoadState('networkidle')
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth
  )
  expect(overflow).toBeLessThanOrEqual(1)
})
