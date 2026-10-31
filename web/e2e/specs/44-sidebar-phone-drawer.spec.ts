import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The sidebar drawer on a phone, upright and on its side:
 *   - the rows start at the drawer's own inset (no rail width reserved inside);
 *   - one scroller: the nav (header and footer pinned) upright, the whole
 *     column on its side, so the footer never clips the nav and iOS has no
 *     nested scroller to rubber-band;
 *   - exactly one filled row (Findings with its Active view fills only Active);
 *   - nothing moves once the slide-in has finished;
 *   - no pin glyph over the counts (pins are not offered in the drawer).
 * Runs on Chromium at phone sizes and on WebKit (iPhone 13) with E2E_WEBKIT=1.
 */

async function openDrawer(page: Page) {
  await page.goto('/findings')
  await expect(page.getByTestId('findings-view-title')).toBeVisible({ timeout: 45_000 })
  await page.locator('[data-sidebar="trigger"]').first().click()
  const drawer = page.locator('[data-mobile="true"]')
  await expect(drawer).toBeVisible()
  // The quick views under Findings arrive with their counts.
  await expect(drawer.getByRole('list', { name: /findings views/i })).toBeVisible({
    timeout: 20_000,
  })
  return drawer
}

for (const size of [
  { name: 'upright', width: 390, height: 664 },
  { name: 'on its side', width: 750, height: 342 },
]) {
  test(
    `sidebar drawer on a phone ${size.name}`,
    { tag: ['@shell', '@phone'] },
    async ({ page }, testInfo) => {
      await page.setViewportSize({ width: size.width, height: size.height })
      const drawer = await openDrawer(page)

      // Sample every row's box for a second once the open animation is over.
      await page.waitForTimeout(600)
      const shift = await drawer.evaluate(async (d) => {
        const rows = () =>
          [
            ...d.querySelectorAll('[data-sidebar="menu-button"],[data-sidebar="menu-sub-button"]'),
          ].map((e) => {
            const r = e.getBoundingClientRect()
            return [r.x, r.y, r.width, r.height]
          })
        const first = rows()
        let max = 0
        for (let i = 0; i < 30; i++) {
          await new Promise((r) => requestAnimationFrame(r))
          const now = rows()
          if (now.length !== first.length) return Number.POSITIVE_INFINITY
          now.forEach((b, j) =>
            b.forEach((v, k) => (max = Math.max(max, Math.abs(v - first[j][k]))))
          )
        }
        return max
      })
      expect(shift, 'rows hold still after the drawer opened').toBeLessThan(1)

      const layout = await drawer.evaluate((d) => {
        const dx = d.getBoundingClientRect().x
        const icons = [...d.querySelectorAll('[data-sidebar="menu-button"] > svg:first-child')].map(
          (e) => e.getBoundingClientRect().x - dx
        )
        const filled = [
          ...d.querySelectorAll('[data-sidebar="menu-button"],[data-sidebar="menu-sub-button"]'),
        ]
          .filter((e) => {
            const bg = getComputedStyle(e).backgroundColor
            return bg !== 'rgba(0, 0, 0, 0)' && bg !== 'transparent'
          })
          .map((e) => (e.textContent ?? '').trim())
        const scrollers = [d, ...d.querySelectorAll('*')].filter((e) => {
          const o = getComputedStyle(e).overflowY
          return (o === 'auto' || o === 'scroll') && e.scrollHeight > e.clientHeight + 1
        })
        const sideways = [d, ...d.querySelectorAll('*')].filter((e) => {
          const o = getComputedStyle(e).overflowX
          return (o === 'auto' || o === 'scroll') && e.scrollWidth > e.clientWidth
        })
        return {
          sideways: sideways.length,
          maxIconInset: Math.max(...icons),
          filled,
          scrollers: scrollers.length,
          pins: d.querySelectorAll('[data-slot="pin-action"]').length,
        }
      })
      expect(layout.maxIconInset, 'row icons sit at the drawer inset').toBeLessThan(24)
      expect(layout.filled, 'exactly one filled row').toHaveLength(1)
      expect(layout.filled[0]).toMatch(/^Active/)
      expect(layout.scrollers, 'one scroller at most').toBeLessThanOrEqual(1)
      expect(layout.pins).toBe(0)
      expect(layout.sideways, 'nothing in the drawer scrolls sideways').toBe(0)

      // Scrolled to the end, the last nav row sits above the footer, in view.
      await drawer.evaluate((d) => {
        for (const sel of ['[data-sidebar="content"]', '[data-slot="sidebar-mobile-scroller"]']) {
          const e = d.querySelector<HTMLElement>(sel)
          if (e) e.scrollTop = e.scrollHeight
        }
      })
      const ends = await drawer.evaluate((d) => {
        const lastRow = [
          ...d.querySelectorAll('[data-sidebar="content"] [data-sidebar="menu-button"]'),
        ].pop()!
        const footer = d.querySelector('[data-slot="sidebar-footer"]')!
        return {
          lastBottom: lastRow.getBoundingClientRect().bottom,
          footerTop: footer.getBoundingClientRect().top,
          footerBottom: footer.getBoundingClientRect().bottom,
          height: d.getBoundingClientRect().height,
        }
      })
      expect(ends.lastBottom).toBeLessThanOrEqual(ends.footerTop + 0.5)
      expect(ends.footerBottom).toBeLessThanOrEqual(ends.height + 0.5)

      await testInfo.attach(`drawer-${size.width}x${size.height}`, {
        body: await page.screenshot(),
        contentType: 'image/png',
      })
    }
  )
}
