import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { seriousAxe } from '../helpers/layout'

/**
 * The closure quality, campaign progress and false-positive widgets (api
 * docs/architecture/dashboards.md, "Closure quality, campaigns and detection
 * quality"): a personal dashboard holding the three renders each widget (its
 * figures or its not-measured message; the false-positive rate is an
 * organization figure) at phone and desktop width, in light and dark, with
 * no horizontal page scroll and no serious or critical accessibility
 * violation.
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
      `quality widgets at ${vp.name} width in ${scheme}`,
      { tag: ['@dashboard'] },
      async ({ page }) => {
        await page.setViewportSize({ width: vp.width, height: vp.height })
        await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
        await page.goto('/')
        const created = await api(page, 'POST', '/api/v1/me/dashboards', {
          name: `e2e-quality-${Math.random().toString(36).slice(2, 8)}`,
          columns: 2,
          layout: [
            widget('w_q1', 'findings.closure_quality', { range: '7d', compare: 'previous_period' }),
            widget('w_q2', 'remediation.campaign_progress'),
            widget('w_q3', 'detection.fp_rate_by_tool', { range: '30d' }),
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
            'Closure quality',
            'Remediation campaign progress',
            'False positives by tool',
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
