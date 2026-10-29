import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { layoutDefects, seriousAxe } from '../helpers/layout'

/**
 * Fix next rows show the shared EPSS bar (a bar for a score, an empty bar and
 * a dash for none) beside the due date, with nothing clipped or overlapping at
 * 1440px and 390px (the bar hides on a phone to keep the title readable), in
 * light and dark.
 */

async function api(page: Page, method: 'POST' | 'DELETE', url: string, data?: unknown) {
  return page.evaluate(
    async ({ method, url, data }) => {
      const r = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: data === undefined ? undefined : JSON.stringify(data),
      })
      return { status: r.status, body: await r.text() }
    },
    { method, url, data }
  )
}

const VIEWPORTS = [
  { name: '1440', width: 1440, height: 900 },
  { name: '390', width: 390, height: 844 },
] as const

for (const vp of VIEWPORTS) {
  for (const scheme of ['light', 'dark'] as const) {
    test(`fix next rows at ${vp.name} in ${scheme}`, { tag: ['@dashboard'] }, async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height })
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
      await page.goto('/dashboards')
      const created = await api(page, 'POST', '/api/v1/me/dashboards', {
        name: `e2e-fix-next-${Math.random().toString(36).slice(2, 8)}`,
        columns: 2,
        layout: [
          {
            widget_type: 'metric',
            x: 0,
            y: 0,
            w: 2,
            h: 3,
            config: {
              v: 2,
              id: 'w_fix',
              data: { kind: 'metric', metric: 'fix.next', filter: {}, time: {}, limit: 5 },
              viz: { type: 'list', options: {} },
            },
          },
        ],
      })
      expect(created.status, `create dashboard: ${created.body.slice(0, 300)}`).toBeLessThan(300)
      const id = (JSON.parse(created.body) as { id: string }).id
      try {
        await api(page, 'POST', `/api/v1/me/dashboards/${id}/default`, {})
        await page.goto('/')
        const rows = page.getByTestId('items-severity-dot')
        const first = rows.first()
        await expect(first).toBeVisible({ timeout: 45_000 })
        await page.waitForLoadState('networkidle')
        if (vp.width >= 640) {
          await expect(
            page.locator('[data-slot=epss-bar]').first(),
            'an EPSS bar on each row at desktop width'
          ).toBeVisible()
        } else {
          await expect(page.locator('[data-slot=epss-bar]').first()).toBeHidden()
        }
        // No row spills past the widget and no row's text boxes overlap.
        const spill = await page.evaluate(() => {
          const out: string[] = []
          for (const li of Array.from(document.querySelectorAll('li'))) {
            if (!li.querySelector('[data-testid=items-severity-dot]')) continue
            const box = li.getBoundingClientRect()
            const card = li.closest('[data-slot=card], section, article') ?? document.body
            const c = card.getBoundingClientRect()
            if (box.right > c.right + 1 || li.scrollWidth > li.clientWidth + 1)
              out.push(li.textContent?.slice(0, 40) ?? '')
            const kids = Array.from(li.querySelectorAll('a > div > *')).map((k) =>
              k.getBoundingClientRect()
            )
            for (let i = 1; i < kids.length; i++) {
              if (
                kids[i].width > 0 &&
                kids[i - 1].width > 0 &&
                kids[i].left < kids[i - 1].right - 1
              )
                out.push(`overlap in ${li.textContent?.slice(0, 40)}`)
            }
          }
          return out
        })
        expect(spill).toEqual([])
        expect(await layoutDefects(page)).toEqual([])
        expect(await seriousAxe(page)).toEqual([])
      } finally {
        await api(page, 'DELETE', `/api/v1/me/dashboards/${id}`)
      }
    })
  }
}
