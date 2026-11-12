import { expect, test } from '@playwright/test'

import type { FixtureSet } from './fixtures/api'
import { layoutIssues } from './layout-checks'
import { MANIFEST } from './manifest'
import { preparePage, settle, unmockedRoutes, useFixtureSet } from './prepare'

/**
 * Layout pass: no reference image. Every manifest page in Vietnamese with the
 * long-data and the empty fixture sets, at each width, must have no sideways
 * page scroll, no clipped text and no overlapping controls (layout-checks.ts).
 * It blocks for every page in the manifest, pending or not: these are defects
 * on any design.
 */

const SETS: FixtureSet[] = ['long', 'empty']

for (const entry of MANIFEST) {
  for (const route of [entry.route, ...(entry.layoutRoutes ?? [])]) {
    for (const set of SETS) {
      for (const width of entry.widths) {
        test(`${entry.id} ${route} vi ${set} ${width}`, async ({ page, baseURL }) => {
          await useFixtureSet(set)
          await preparePage(page, { baseURL: baseURL!, theme: 'light', locale: 'vi', width })
          await page.goto(route)
          await settle(page, entry.page.ready)

          expect(await page.locator('html').getAttribute('lang')).toBe('vi')
          expect(await unmockedRoutes(), 'routes no fixture answers').toEqual([])
          const issues = await page.evaluate(layoutIssues)
          expect(issues, 'layout issues').toEqual([])
        })
      }
    }
  }
}
