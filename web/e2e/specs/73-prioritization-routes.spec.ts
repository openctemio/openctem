import { test, expect } from '../fixtures/authenticated-page'

/**
 * The Prioritization routes render, at phone and desktop width, and the Sync
 * status tab of Threat intelligence shows a feed this console has no entry for.
 *
 * Owner report 2026-11-14 (phone): "Prioritization Error" on /threat-intel. The
 * API listed a feed ("vulnfeed") next to epss and kev; the Sync status tab read
 * a display entry that did not exist and the route's error boundary caught it.
 * The stats answer carries that third feed here, as the live API sent it.
 */

const ROUTES = [
  '/attack-paths',
  '/business-impact',
  '/emerging-threats',
  '/exposure-chains',
  '/priority-rules',
  '/threat-intel',
  '/vulnerabilities',
]

for (const [name, size] of [
  ['phone', { width: 390, height: 844 }],
  ['desktop', { width: 1440, height: 900 }],
] as const) {
  test.describe(`prioritization routes at ${name}`, () => {
    test.use({ viewport: size })

    for (const route of ROUTES) {
      test(
        `${route} renders without the error boundary`,
        { tag: ['@prioritization'] },
        async ({ page }) => {
          const pageErrors: string[] = []
          page.on('pageerror', (e) => pageErrors.push(e.message))
          await page.goto(route)
          await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible({
            timeout: 30_000,
          })
          await expect(page.getByText('Prioritization Error')).toHaveCount(0)
          expect(pageErrors).toEqual([])
        }
      )
    }

    test(
      'threat intel sync tab lists a feed the console has no entry for',
      { tag: ['@prioritization'] },
      async ({ page }) => {
        const pageErrors: string[] = []
        page.on('pageerror', (e) => pageErrors.push(e.message))
        await page.route('**/api/v1/threat-intel/stats', async (route) => {
          const res = await route.fetch()
          const body = await res.json()
          const row = (source: string) => ({
            source,
            enabled: true,
            last_sync_status: 'success',
            records_synced: 1,
            last_sync_at: new Date().toISOString(),
          })
          await route.fulfill({
            response: res,
            json: {
              ...body,
              sync_statuses: [row('epss'), row('kev'), row('vulnfeed'), row('future-feed')],
            },
          })
        })
        await page.goto('/threat-intel?tab=sync')
        await expect(page.getByText('future-feed')).toBeVisible({ timeout: 30_000 })
        await expect(page.getByText('Vulnerability feed')).toBeVisible()
        await expect(page.getByText('Prioritization Error')).toHaveCount(0)
        expect(pageErrors).toEqual([])
      }
    )
  })
}
