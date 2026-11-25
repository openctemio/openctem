import { test, expect } from '../fixtures/authenticated-page'

/**
 * Attack surface > Posture (server/docs/architecture/easm-posture.md): the
 * Overview's posture section opens the page, the page shows a grade or why there is none, and the
 * overview card links to it.
 */

const POSTURE = '/attack-surface/posture'

test(
  'the Overview posture section opens a graded page',
  { tag: ['@attack-surface'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/attack-surface')
    const tabs = page.getByRole('navigation', { name: 'Attack surface sections' })
    await expect(tabs).toBeVisible({ timeout: 30_000 })
    await expect(page.getByTestId('posture-card')).toBeVisible()
    // Posture is not a tab (one tab level per screen): the Overview links to it.
    await expect(tabs.getByRole('link', { name: 'Posture' })).toHaveCount(0)
    await page.getByRole('link', { name: 'View posture details' }).click()
    await expect(page).toHaveURL(new RegExp(`${POSTURE}$`))
    await page.waitForLoadState('networkidle')
    // Either a grade, or the reason there is none yet.
    await expect(
      page
        .getByRole('img', { name: /^Grade [ABCDF], score \d+ of 100$/ })
        .or(page.getByText(/first posture computation is running|No surface asset in your view/))
        .first()
    ).toBeVisible()
    await expect(page.getByText('How the score works')).toBeVisible()
    // The Overview tab stays the open one.
    await expect(tabs.getByRole('link', { name: 'Overview' })).toHaveAttribute(
      'aria-current',
      'page'
    )
  }
)

test('the posture page fits a phone', { tag: ['@attack-surface'] }, async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(POSTURE)
  await page.waitForLoadState('networkidle')
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth
  )
  expect(overflow).toBeLessThanOrEqual(1)
})
