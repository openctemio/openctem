import fs from 'fs'
import path from 'path'
import { checkAt as checkAnatomy, open } from '../helpers/page-anatomy'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Page anatomy on EVERY page of the console (research/244, 249 R21).
 *
 * The routes are read from the app directory, so a new page is checked the
 * day it is added; nothing has to remember to list it. Each page is measured
 * at 1440px and at 390px from bounding boxes:
 *
 * - the page's blocks sit in a `PageStack`;
 * - page header to its tab strip 16px, every other gap between blocks 24px (the --sp-section and --sp-page tokens, read from the page)
 *   (nested stacks flattened, so a tab panel's blocks count);
 * - one tab row per page, no segmented control used as a row filter;
 * - tab icons: all tabs of a strip have one or none does, 16px; no tab label
 *   cut at the strip's edge (a strip that does not fit moves tabs to More);
 * - a metric strip: at most five tiles, each a link or a filter toggle, no
 *   sideways scroll, at most two rows on a phone (three for five tiles with
 *   detail lines, which never sit in thirds);
 * - chips never wrap onto a second line and hold no " · ";
 * - an empty list shows no pagination ("Showing 0 - 0 of 0", "Page 1 of 0");
 * - a table's name column keeps a readable width at 1440px;
 * - no horizontal page scroll;
 * - controls side by side in a row (buttons, fields, selects) share one
 *   height and one centre line (probeRowMix; open rows are listed in
 *   ROW_MIX_DEBT in helpers/page-anatomy.ts, which only shrinks);
 * - a settings page (/settings, /account) shows no Save button at rest: its
 *   form saves through the sticky SettingsSaveBar, shown while there are
 *   unsaved changes (SAVE_EXCEPTIONS lists the pages not moved yet);
 * - no hand-made "Insufficient permissions" / "Access Denied" text: a refusal
 *   is the shared access notice;
 * - the page renders: no error boundary ("Something went wrong") and no
 *   uncaught page error (a server page calling a client hook crashed
 *   /notifications on every visit with nothing visiting it).
 *
 * A page that cannot follow a rule is listed in EXCEPTIONS with the reason.
 */

const APP = path.resolve(__dirname, '../../src/app/(dashboard)')

/** Static routes of the dashboard shell, from its page files. */
function staticRoutes(): string[] {
  const out: string[] = []
  const walk = (dir: string, segs: string[]) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!e.isDirectory()) {
        if (e.name === 'page.tsx') out.push('/' + segs.filter(Boolean).join('/'))
        continue
      }
      if (e.name.startsWith('_') || e.name === '__tests__' || e.name.startsWith('@')) continue
      const seg = /^\(.*\)$/.test(e.name) ? '' : e.name
      walk(path.join(dir, e.name), [...segs, seg])
    }
  }
  walk(APP, [])
  return [...new Set(out)].filter((r) => !r.includes('[')).sort()
}

/**
 * Detail pages, opened on the first row the seeded organization has. The id
 * comes from the list endpoint through the console's own proxy.
 */
const DETAIL_ROUTES: { route: string; list: string; key?: string }[] = [
  { route: '/assets/{id}', list: '/api/v1/assets?per_page=1' },
  { route: '/assets/groups/{id}', list: '/api/v1/asset-groups?per_page=1' },
  { route: '/components/{id}', list: '/api/v1/components?per_page=1' },
  { route: '/findings/{id}', list: '/api/v1/findings?per_page=1' },
  { route: '/scans/{id}', list: '/api/v1/scans?per_page=1' },
  { route: '/remediation/campaigns/{id}', list: '/api/v1/remediation/campaigns?per_page=1' },
  { route: '/remediation/tasks/{id}', list: '/api/v1/remediation/tasks?per_page=1' },
  { route: '/pentest/campaigns/{id}', list: '/api/v1/pentest/campaigns?per_page=1' },
  {
    route: '/vulnerabilities/{id}',
    list: '/api/v1/vulnerability-exposures?per_page=1',
    key: 'cve_id',
  },
]

/** Pages that are not a page of blocks, with the reason. */
const EXCEPTIONS: Record<string, string> = {
  // Not pages: they only redirect or finish a flow.
  '/settings/tenant/create': 'creates an organization, then leaves',
  '/ci-cd/github-app/callback': 'finishes the GitHub App install, then leaves',
}

/**
 * Detail and editor pages with their own header layout (DetailHeader, a
 * full-width editor): the block rhythm is not checked there, every other rule
 * is. Their text layout is covered by 30-drawer-text-layout.
 */
const OWN_LAYOUT = [/^\/findings\/(?!approvals$)[^/]+$/, /^\/remediation\/campaigns\/[^/]+$/]

for (const route of staticRoutes()) {
  if (EXCEPTIONS[route]) continue
  test(`page anatomy on ${route}`, { tag: ['@shell'] }, async ({ page }, info) => {
    test.skip(!(await open(page, route)), `${route} redirects`)
    // The page renders a block layout once its header is drawn.
    await expect(page.locator('main h1').first()).toBeVisible({ timeout: 30_000 })
    for (const width of [1440, 390])
      await checkAnatomy(page, route, width, OWN_LAYOUT, { rowMix: true })
    if (info.errors.length > 0) {
      await info.attach(route, { body: await page.screenshot(), contentType: 'image/png' })
    }
  })
}

for (const { route, list, key } of DETAIL_ROUTES) {
  test(`page anatomy on ${route}`, { tag: ['@shell'] }, async ({ page }) => {
    await page.goto('/')
    const id = await page.evaluate(
      async ({ url, field }) => {
        const res = await fetch(url, { credentials: 'same-origin' })
        if (!res.ok) return null
        const body = await res.json()
        const rows = body.data ?? body.items ?? body
        return Array.isArray(rows) && rows[0]?.[field] ? String(rows[0][field]) : null
      },
      { url: list, field: key ?? 'id' }
    )
    test.skip(!id, `no row to open for ${route}`)
    const url = route.replace('{id}', encodeURIComponent(id!))
    await open(page, url)
    await expect(page.locator('main h1').first()).toBeVisible({ timeout: 30_000 })
    for (const width of [1440, 390])
      await checkAnatomy(page, url, width, OWN_LAYOUT, { rowMix: true })
  })
}

/**
 * A list toolbar with a chips row takes at most two rows on a phone: the
 * search, then Add filter and the chips with the end group (views, group,
 * display) and the count. Before, the end group had a line of its own (three
 * rows before the data on /findings). A list whose locked chip takes a line of
 * its own on a phone (/assets with names hidden) has one more.
 */
for (const route of ['/findings']) {
  test(
    `list toolbar keeps two rows on a phone on ${route}`,
    { tag: ['@shell'] },
    async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto(route)
      const region = page.locator('[data-slot="list-toolbar-region"]').first()
      await expect(region).toBeVisible({ timeout: 30_000 })
      await expect(region.locator('[data-slot="list-search-input"]').first()).toBeVisible()
      const rows = await region.evaluate((el) => {
        const centers: number[] = []
        for (const c of el.querySelectorAll<HTMLElement>('button, input, a')) {
          const r = c.getBoundingClientRect()
          if (r.width > 0 && r.height > 0) centers.push(r.top + r.height / 2)
        }
        centers.sort((a, b) => a - b)
        // A new row starts where a control's middle is more than 16px lower.
        return centers.filter((c, i) => i === 0 || c - centers[i - 1] > 16).length
      })
      expect(rows, `${route}: toolbar rows at 390px`).toBeLessThanOrEqual(2)
    }
  )
}
