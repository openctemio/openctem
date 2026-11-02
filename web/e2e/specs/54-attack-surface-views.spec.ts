import { test, expect } from '../fixtures/authenticated-page'

/**
 * Attack surface navigation (research/353 D1, D2): one strip of at most five
 * views that fits without a "More" menu, and a lens for the routes of the
 * open view. At 390 px nothing scrolls sideways.
 */

const SIZES = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'phone', width: 390, height: 844 },
]

for (const size of SIZES) {
  test(`five views and a lens (${size.name})`, { tag: ['@attack-surface'] }, async ({ page }) => {
    await page.setViewportSize({ width: size.width, height: size.height })
    await page.goto('/attack-surface/certificates')
    const strip = page.getByRole('navigation', { name: 'Attack surface sections' })
    await expect(strip).toBeVisible({ timeout: 30_000 })
    const links = strip.getByRole('link')
    expect(await links.count()).toBeLessThanOrEqual(5)
    await expect(strip.getByRole('link', { name: 'Inventory' })).toHaveAttribute(
      'aria-current',
      'page'
    )
    if (size.width >= 1024) {
      // Five short labels fit: no overflow menu hides a view.
      await expect(page.locator('[data-slot=tabs-more]')).toHaveCount(0)
    }
    const lens = page.getByRole('radiogroup', { name: 'Inventory views' })
    await expect(lens).toBeVisible()
    await expect(lens.getByRole('radio', { name: 'Certificates' })).toHaveAttribute(
      'aria-checked',
      'true'
    )
    await lens.getByRole('radio', { name: 'Technologies' }).click()
    await expect(page).toHaveURL(/\/attack-surface\/technologies$/)
    await expect(strip.getByRole('link', { name: 'Inventory' })).toHaveAttribute(
      'aria-current',
      'page'
    )
    const [scroll, inner] = await page.evaluate(() => [
      document.documentElement.scrollWidth,
      window.innerWidth,
    ])
    expect(scroll).toBeLessThanOrEqual(inner)
  })
}

test('Changes is a view of its own', { tag: ['@attack-surface'] }, async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/attack-surface/changes')
  const strip = page.getByRole('navigation', { name: 'Attack surface sections' })
  await expect(strip).toBeVisible({ timeout: 30_000 })
  await expect(strip.getByRole('link', { name: 'Changes' })).toHaveAttribute('aria-current', 'page')
})
