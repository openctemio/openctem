import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The sidebar header's two trailing icons sit on one vertical axis: the
 * collapse button on the brand row and the chevron on the organization row
 * below it. Their bounding-box centres differ by at most 1 px horizontally,
 * on the desktop sidebar at 1440 and in the phone drawer at 390, and they are
 * the same size.
 */

async function iconCentres(page: Page, scope: string) {
  return page.evaluate((sel) => {
    const root = document.querySelector(sel)!
    const centre = (e: Element) => {
      const b = e.getBoundingClientRect()
      return { x: b.left + b.width / 2, w: b.width, h: b.height }
    }
    return {
      panel: centre(root.querySelector('[data-sidebar="trigger"] svg')!),
      chevron: centre(root.querySelector('[data-testid="team-switcher-chevron"]')!),
    }
  }, scope)
}

test.describe('Sidebar header icons share one axis', { tag: ['@shell', '@phone'] }, () => {
  test('desktop 1440', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/')
    const scope = '[data-slot="sidebar-container"] [data-sidebar="sidebar"]'
    await expect(page.locator(scope).first()).toBeVisible({ timeout: 45_000 })
    const { panel, chevron } = await iconCentres(page, scope)
    expect(Math.abs(panel.x - chevron.x), 'icon centres, x').toBeLessThanOrEqual(1)
    expect(Math.abs(panel.w - chevron.w), 'icon width').toBeLessThanOrEqual(0.5)
    expect(Math.abs(panel.h - chevron.h), 'icon height').toBeLessThanOrEqual(0.5)
  })

  test('phone drawer 390', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/')
    await page.locator('[data-sidebar="trigger"]').first().click()
    const scope = '[data-mobile="true"]'
    await expect(page.locator(scope)).toBeVisible({ timeout: 45_000 })
    await page.waitForTimeout(500)
    const { panel, chevron } = await iconCentres(page, scope)
    expect(Math.abs(panel.x - chevron.x), 'icon centres, x').toBeLessThanOrEqual(1)
    expect(Math.abs(panel.w - chevron.w), 'icon width').toBeLessThanOrEqual(0.5)
  })
})
