import { test, expect } from '../fixtures/authenticated-page'

/**
 * Exploration (api docs/architecture/exploration.md): the page opens with its
 * status sentence and the grouped list; an empty group says so. At desktop
 * and phone width, without sideways scroll.
 */

test('the Exploration page loads its groups', { tag: ['@scans'] }, async ({ page }) => {
  for (const viewport of [
    { width: 1280, height: 900 },
    { width: 390, height: 844 },
  ]) {
    await page.setViewportSize(viewport)
    await page.goto('/exploration?group=running')
    await expect(page.getByRole('heading', { name: 'Exploration' })).toBeVisible({
      timeout: 30_000,
    })
    await expect(page.getByTestId('exploration-status')).toBeVisible()
    // The group is a filter token whose name carries its value.
    await expect(page.getByRole('button', { name: 'Steps: Running' })).toBeVisible()
    // Either the empty state or at least one step.
    await expect(
      page.getByText('Nothing is running.').or(page.getByTestId('exploration-lead').first())
    ).toBeVisible()
    const sideways = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth
    )
    expect(sideways, `page scrolls sideways at ${viewport.width}px`).toBeLessThanOrEqual(0)
  }
})
