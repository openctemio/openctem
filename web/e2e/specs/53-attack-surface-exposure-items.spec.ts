import { test, expect } from '../fixtures/authenticated-page'
import { layoutDefects, seriousAxe } from '../helpers/layout'

/**
 * Attack surface > Exposure items at 1440 px and 390 px, in the list and the
 * group-by-asset view: no sideways scroll or other layout defect, no serious
 * axe violation, the tab is selected, and the list asks for open exposures
 * on monitored assets by default.
 */

for (const width of [1440, 390]) {
  for (const path of ['/attack-surface/exposures', '/attack-surface/exposures?view=assets']) {
    test(`${path} at ${width}px`, { tag: ['@attack-surface'] }, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      const lists: string[] = []
      page.on('request', (r) => {
        const u = new URL(r.url())
        if (u.pathname.startsWith('/api/v1/attack-surface/exposures'))
          lists.push(u.pathname + u.search)
      })
      await page.goto(path)
      await expect(
        page.locator('main#content').getByRole('heading', { level: 1, name: 'Attack surface' })
      ).toBeVisible({ timeout: 30_000 })
      await page.waitForLoadState('networkidle')
      expect(await layoutDefects(page)).toEqual([])
      expect(await seriousAxe(page)).toEqual([])
      const decoded = lists.map((l) => decodeURIComponent(l))
      const main = decoded.find((l) => !l.includes('/stats'))
      expect(main, decoded.join('\n')).toContain('state=active,in_progress')
      expect(main, decoded.join('\n')).toContain('asset_monitoring_state=monitored')
    })
  }
}
