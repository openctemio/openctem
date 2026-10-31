import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { seriousAxe } from '../helpers/layout'

/**
 * The notifications bell popover fits its content up to about 70% of the
 * window: with few items it shrinks to fit (no empty area under "View all
 * notifications"), with many only the item list scrolls (one scroll
 * container, one scrollbar), and the header and the footer stay visible.
 * Measured at 1440px and 390px, in light and dark.
 */

function notifications(n: number) {
  return Array.from({ length: n }, (_, i) => ({
    id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
    tenant_id: '00000000-0000-4000-8000-0000000000aa',
    audience: 'user',
    notification_type: 'finding_assigned',
    title: `Notification ${i + 1} with a title long enough to wrap onto a second line in the popover`,
    body: 'A body line for the notification.',
    severity: 'info',
    is_read: false,
    created_at: new Date(Date.now() - i * 60_000).toISOString(),
  }))
}

async function openBell(page: Page, n: number) {
  await page.route(/\/api\/v1\/notifications(\?.*)?$/, (route) =>
    route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({
        data: notifications(n),
        total: n,
        page: 1,
        per_page: 20,
        total_pages: 1,
      }),
    })
  )
  await page.goto('/')
  await page.getByRole('button', { name: /^Notifications/ }).click()
  const pop = page.locator('[data-slot=popover-content]')
  await expect(pop).toBeVisible()
  await expect(pop.getByRole('link', { name: 'View all notifications' })).toBeVisible()
  await page.waitForTimeout(400)
  return pop
}

const VIEWPORTS = [
  { name: '1440', width: 1440, height: 900 },
  { name: '390', width: 390, height: 844 },
] as const

for (const vp of VIEWPORTS) {
  for (const scheme of ['light', 'dark'] as const) {
    for (const n of [0, 3, 30]) {
      test(
        `bell popover with ${n} items at ${vp.name} in ${scheme}`,
        { tag: ['@shell'] },
        async ({ page }) => {
          await page.setViewportSize({ width: vp.width, height: vp.height })
          await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
          const pop = await openBell(page, n)
          const m = await pop.evaluate((el) => {
            const box = el.getBoundingClientRect()
            const scrollers = [el, ...Array.from(el.querySelectorAll('*'))].filter((e) => {
              const s = getComputedStyle(e)
              return /(auto|scroll)/.test(s.overflowY) && e.scrollHeight > e.clientHeight + 1
            })
            const link = Array.from(el.querySelectorAll('a')).find((a) =>
              /View all notifications/.test(a.textContent ?? '')
            )!
            const lb = link.getBoundingClientRect()
            return {
              top: box.top,
              height: box.height,
              bottom: box.bottom,
              scrollers: scrollers.length,
              names: scrollers
                .map(
                  (e) =>
                    e.tagName +
                    '.' +
                    (e.getAttribute('data-slot') ?? e.className).slice(0, 60) +
                    ' ' +
                    e.clientHeight +
                    '/' +
                    e.scrollHeight
                )
                .join(' | '),
              scrollbars: el.querySelectorAll('[data-slot=scroll-area-scrollbar]').length,
              footerBottomGap: box.bottom - lb.bottom,
              footerInView: lb.bottom <= window.innerHeight && lb.top >= 0,
              vh: window.innerHeight,
              pageScrollX:
                document.documentElement.scrollWidth - document.documentElement.clientWidth,
            }
          })
          expect(m.footerInView, 'footer visible').toBe(true)
          expect(m.height, 'at most 70% of the window').toBeLessThanOrEqual(m.vh * 0.7 + 1)
          expect(m.footerBottomGap, 'no empty area under the footer').toBeLessThanOrEqual(14)
          expect(m.pageScrollX).toBeLessThanOrEqual(0)
          if (n === 30) {
            expect(m.scrollers, m.names).toBe(1)
          } else {
            expect(m.scrollers, 'nothing scrolls with few items').toBe(0)
          }
          if (n === 3) {
            expect(m.height, 'fits its content').toBeLessThan(m.vh * 0.5)
          }
          expect(await seriousAxe(page, '[data-slot=popover-content]')).toEqual([])
        }
      )
    }
  }
}
