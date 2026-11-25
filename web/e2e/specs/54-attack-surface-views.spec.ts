import { test, expect } from '../fixtures/authenticated-page'

/**
 * Attack surface navigation: one tab level per screen (owner rule
 * 2026-11-24). One strip of tabs, no segmented route lens under it; a strip
 * wider than the screen is one swipe row with an edge fade. At 390 px the page
 * never scrolls sideways.
 */

const SIZES = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'phone', width: 390, height: 844 },
]

for (const size of SIZES) {
  test(
    `one tab row, no lens under it (${size.name})`,
    { tag: ['@attack-surface'] },
    async ({ page }) => {
      await page.setViewportSize({ width: size.width, height: size.height })
      await page.goto('/attack-surface/certificates')
      const strip = page.getByRole('navigation', { name: 'Attack surface sections' })
      await expect(strip).toBeVisible({ timeout: 30_000 })
      await expect(strip.getByRole('link', { name: 'Certificates' })).toHaveAttribute(
        'aria-current',
        'page'
      )
      await expect(page.locator('main [data-testid="segmented-lens"]')).toHaveCount(0)
      await strip.getByRole('link', { name: 'Technologies' }).click()
      await expect(page).toHaveURL(/\/attack-surface\/technologies$/)
      await expect(strip.getByRole('link', { name: 'Technologies' })).toHaveAttribute(
        'aria-current',
        'page'
      )
      const [scroll, inner] = await page.evaluate(() => [
        document.documentElement.scrollWidth,
        window.innerWidth,
      ])
      expect(scroll).toBeLessThanOrEqual(inner)
    }
  )
}

test(
  'Changes and Page changes are tabs of their own',
  { tag: ['@attack-surface'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/attack-surface/changes')
    const strip = page.getByRole('navigation', { name: 'Attack surface sections' })
    await expect(strip).toBeVisible({ timeout: 30_000 })
    await expect(strip.getByRole('link', { name: 'Changes', exact: true })).toHaveAttribute(
      'aria-current',
      'page'
    )
    await expect(strip.getByRole('link', { name: 'Page changes' })).toBeVisible()
    await expect(page.locator('main [data-testid="segmented-lens"]')).toHaveCount(0)
  }
)
