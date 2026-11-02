import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { seriousAxe } from '../helpers/layout'

/**
 * The attack surface and accepted-risk widgets (api
 * docs/architecture/dashboards.md, "Attack surface and accepted risk"): a
 * personal dashboard holding "New on the attack surface", "Certificate
 * expiry" and "Accepted risks ending" renders each widget at phone and
 * desktop width, in light and dark, with no horizontal page scroll and no
 * serious or critical accessibility violation.
 */

const VIEWPORTS = [
  { name: 'phone', width: 390, height: 844 },
  { name: 'desktop', width: 1440, height: 900 },
] as const

const widget = (id: string, metric: string, time: Record<string, string> = {}) => ({
  widget_type: 'metric',
  x: 0,
  y: 0,
  w: 6,
  h: 2,
  config: {
    v: 2,
    id,
    data: { kind: 'metric', metric, filter: {}, time },
    viz: { type: 'bar', options: {} },
  },
})

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

for (const vp of VIEWPORTS) {
  for (const scheme of ['light', 'dark'] as const) {
    test(
      `attack surface widgets at ${vp.name} width in ${scheme}`,
      { tag: ['@dashboard'] },
      async ({ page }) => {
        await page.setViewportSize({ width: vp.width, height: vp.height })
        await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
        await page.goto('/')
        const created = await api(page, 'POST', '/api/v1/me/dashboards', {
          name: `e2e-surface-${Math.random().toString(36).slice(2, 8)}`,
          columns: 2,
          layout: [
            widget('w_s1', 'surface.new_assets', { range: '7d', compare: 'previous_period' }),
            widget('w_s2', 'certificates.expiry'),
            widget('w_s3', 'exceptions.expiring'),
          ],
        })
        test.skip(created.status >= 300, 'dashboard could not be created')
        const id = (JSON.parse(created.body) as { id: string }).id
        try {
          await page.evaluate((ref) => {
            try {
              localStorage.setItem('openctem:dashboard-choice', ref)
            } catch {
              /* private mode: the default dashboard opens instead */
            }
          }, `personal:${id}`)
          await page.reload()
          for (const name of [
            'New on the attack surface',
            'Certificate expiry',
            'Accepted risks ending',
          ]) {
            await expect(page.getByText(name, { exact: true }).first()).toBeVisible({
              timeout: 45_000,
            })
          }
          await page.waitForLoadState('networkidle')
          if (vp.width < 768) {
            const overflow = await page.evaluate(
              () => document.documentElement.scrollWidth - document.documentElement.clientWidth
            )
            expect(overflow, 'horizontal page scroll on a phone').toBeLessThanOrEqual(0)
          }
          expect(await seriousAxe(page)).toEqual([])
        } finally {
          await api(page, 'DELETE', `/api/v1/me/dashboards/${id}`)
        }
      }
    )
  }
}
