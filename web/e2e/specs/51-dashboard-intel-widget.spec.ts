import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { seriousAxe } from '../helpers/layout'

/**
 * The emerging-threats widget (api docs/architecture/dashboards.md,
 * "Emerging threats" and "Module awareness"): a personal dashboard holding
 * "Emerging threats affecting you" renders it at phone and desktop width, in
 * light and dark, with no horizontal page scroll and no serious or critical
 * accessibility violation, or hides it when the organization has the threat
 * intelligence module off. The emerging-threats list opens with the filters
 * of its URL, as a dashboard level link sends them.
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

async function api(page: Page, method: 'GET' | 'POST' | 'DELETE', url: string, data?: unknown) {
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
      `emerging threats widget at ${vp.name} width in ${scheme}`,
      { tag: ['@dashboard'] },
      async ({ page }) => {
        await page.setViewportSize({ width: vp.width, height: vp.height })
        await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
        await page.goto('/')
        const catalog = await api(page, 'GET', '/api/v1/me/dashboards/widget-catalog')
        const offered = catalog.body.includes('"intel.emerging_threats"')
        const created = await api(page, 'POST', '/api/v1/me/dashboards', {
          name: `e2e-intel-${Math.random().toString(36).slice(2, 8)}`,
          columns: 2,
          layout: [widget('w_i1', 'intel.emerging_threats'), widget('w_i2', 'intel.kev_open')],
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
          await expect(page.getByText('KEV on your assets', { exact: true }).first()).toBeVisible({
            timeout: 45_000,
          })
          const title = page.getByText('Emerging threats affecting you', { exact: true })
          if (offered) {
            await expect(title.first()).toBeVisible({ timeout: 45_000 })
          } else {
            // The module is off: the widget is not drawn at all.
            await expect(title).toHaveCount(0)
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

test(
  'the emerging-threats list opens with the filters of its URL',
  { tag: ['@dashboard'] },
  async ({ page }) => {
    await page.goto('/')
    const list = await api(
      page,
      'GET',
      '/api/v1/emerging-threats/?level=digest&state=all&per_page=1'
    )
    test.skip(list.status !== 200, 'emerging threats are not available for this organization')
    await page.goto('/emerging-threats?level=digest&state=all')
    await expect(page.locator('#et-level')).toContainText('Digest', { timeout: 45_000 })
    await expect(page.locator('#et-state')).toContainText('All states')
    // A filter change is written back to the address.
    await page.getByRole('switch', { name: 'Internet-facing only' }).click()
    await expect(page).toHaveURL(/exposure=internet/)
    await expect(page).toHaveURL(/level=digest/)
  }
)
