import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Settings and Help (the sidebar footer) stay at the bottom of the sidebar
 * while the nav scrolls on its own: on the desktop sidebar at a short and a
 * tall window, and in the phone drawer upright. (A phone on its side scrolls
 * the whole drawer column: 44-sidebar-phone-drawer.)
 */

async function footerBox(sidebar: Locator) {
  return sidebar.evaluate((s) => {
    const footer = s.querySelector('[data-sidebar="footer"]')!
    const content = s.querySelector<HTMLElement>('[data-sidebar="content"]')!
    content.scrollTop = content.scrollHeight
    return {
      sidebarBottom: s.getBoundingClientRect().bottom,
      footerBottom: footer.getBoundingClientRect().bottom,
      footerTop: footer.getBoundingClientRect().top,
      viewport: window.innerHeight,
      contentScrolls: content.scrollHeight > content.clientHeight,
    }
  })
}

async function expectPinned(sidebar: Locator, page: Page) {
  const box = await footerBox(sidebar)
  expect(
    Math.abs(box.footerBottom - box.sidebarBottom),
    'footer at the sidebar bottom'
  ).toBeLessThan(1)
  expect(box.footerBottom, 'footer inside the viewport').toBeLessThanOrEqual(box.viewport + 0.5)
  expect(box.footerTop, 'footer visible').toBeLessThan(box.viewport)
  await expect(sidebar.getByRole('link', { name: /^settings$/i })).toBeInViewport()
  return { box, page }
}

test.describe('Sidebar footer stays pinned', { tag: ['@shell', '@phone'] }, () => {
  for (const height of [700, 1000]) {
    test(`desktop 1440x${height}`, async ({ page }) => {
      await page.setViewportSize({ width: 1440, height })
      for (const route of ['/findings', '/settings/general']) {
        await page.goto(route)
        const sidebar = page
          .locator('[data-slot="sidebar-container"] [data-sidebar="sidebar"]')
          .first()
        await expect(sidebar).toBeVisible({ timeout: 45_000 })
        await expectPinned(sidebar, page)
      }
    })
  }

  test('phone drawer upright 390x664', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 664 })
    await page.goto('/settings/general')
    await page.locator('[data-sidebar="trigger"]').first().click()
    const drawer = page.locator('[data-mobile="true"]')
    await expect(drawer).toBeVisible({ timeout: 45_000 })
    // Let the slide-in finish.
    await page.waitForTimeout(500)
    const { box } = await expectPinned(drawer, page)
    expect(box.contentScrolls, 'the settings nav is taller than the drawer').toBe(true)
  })
})
