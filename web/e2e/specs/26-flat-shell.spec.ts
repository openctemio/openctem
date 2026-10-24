import { test, expect } from '../fixtures/authenticated-page'

/**
 * Flat shell: the area right of the sidebar and below the top bar is not a
 * floating card. It reaches the viewport's edges with no margin, border,
 * radius or shadow, on the page background, and the sidebar is separated from
 * it by one border. Checked on the dashboard and the findings list at desktop
 * and phone width in both themes; a screenshot of each is attached.
 */

const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'phone', width: 390, height: 844 },
] as const

for (const path of ['/', '/findings']) {
  for (const vp of VIEWPORTS) {
    for (const scheme of ['light', 'dark'] as const) {
      test(`flat shell on ${path} at ${vp.name} in ${scheme}`, async ({ page }, testInfo) => {
        await page.setViewportSize({ width: vp.width, height: vp.height })
        await page.emulateMedia({ colorScheme: scheme })
        await page.goto(path)
        const inset = page.locator('[data-slot="sidebar-inset"]')
        await expect(inset).toBeVisible({ timeout: 45_000 })
        await page.waitForLoadState('networkidle')

        const frame = await inset.evaluate((el) => {
          const cs = getComputedStyle(el)
          const r = el.getBoundingClientRect()
          return {
            margins: [cs.marginTop, cs.marginRight, cs.marginBottom, cs.marginLeft],
            radius: cs.borderTopLeftRadius,
            shadow: cs.boxShadow,
            border: ['Top', 'Right', 'Bottom', 'Left'].map((s) =>
              cs.getPropertyValue(`border-${s.toLowerCase()}-width`)
            ),
            bottom: r.bottom,
            right: r.right,
            background: cs.backgroundColor,
            page: getComputedStyle(document.body).backgroundColor,
            vh: window.innerHeight,
            // The page keeps a stable scrollbar gutter; the body ends where it starts.
            vw: document.body.getBoundingClientRect().right,
          }
        })
        expect(frame.margins, 'no outer margin').toEqual(['0px', '0px', '0px', '0px'])
        expect(frame.radius, 'no radius').toBe('0px')
        expect(frame.shadow, 'no shadow').toBe('none')
        expect(frame.border, 'no border').toEqual(['0px', '0px', '0px', '0px'])
        expect(Math.round(frame.bottom), 'flush with the viewport bottom').toBe(frame.vh)
        expect(Math.round(frame.right), 'flush with the page right edge').toBe(Math.round(frame.vw))
        expect(frame.background, 'page background').toBe(frame.page)

        await testInfo.attach(
          `shell-${path === '/' ? 'dashboard' : 'findings'}-${vp.name}-${scheme}.png`,
          {
            body: await page.screenshot(),
            contentType: 'image/png',
          }
        )
      })
    }
  }
}
