import { test, expect, type Page } from '@playwright/test'
import { checkAt, open } from '../../../e2e/helpers/page-anatomy'
import { wcagViolations } from '../../../e2e/helpers/axe'
import { findBreaks, formatBreaks, type Scenario } from '../../../e2e/helpers/text-breaks'
import { ensureElevated } from '../helpers/session'
import { CONSOLE_LIST_DATA, consoleListData } from '../helpers/rich-data'
import {
  DETAIL_ROUTES,
  dynamicPatterns,
  navRoutes,
  pageRoutes,
  staticRoutes,
} from '../helpers/routes'

/**
 * Every page of the console, at 1440x900 and 390x844, signed in and elevated
 * (the pages show their content, not the notice that asks for the elevation).
 *
 * The routes come from the app directory (every page.tsx) and the navigation
 * config (config/admin-nav.ts), so a page is checked the day it is added and a
 * moved page is followed without editing this file. A page file with a path
 * parameter must be listed in DETAIL_ROUTES (opened on the first row of its
 * list), or the suite fails: no page goes unvisited.
 *
 * Per page: it renders (no error boundary, no page error, no console error),
 * one h1, no sideways scroll, axe WCAG 2.2 AA with no critical or serious
 * violation, no " · " and no em dash in the visible text, and the page anatomy
 * the tenant app's suite checks (web/e2e/helpers/page-anatomy.ts).
 */

const VIEWPORTS = [
  { width: 1440, height: 900 },
  { width: 390, height: 844 },
]

type BreakVariant = {
  tag: string
  width: number
  height: number
  lang: 'en' | 'vi'
  theme: 'light' | 'dark'
  scen: Scenario
  rowMenu?: boolean
}
const PHONE = { width: 390, height: 844 }
const LAYOUT_OUT = process.env.CONSOLE_LAYOUT_OUT
const BREAK_VARIANTS: BreakVariant[] = [
  { tag: 'p-en', ...PHONE, lang: 'en', theme: 'light', scen: 'rich' },
  { tag: 'p-en-dark', ...PHONE, lang: 'en', theme: 'dark', scen: 'rich' },
  { tag: 'p-vi', ...PHONE, lang: 'vi', theme: 'light', scen: 'rich' },
  { tag: 't-en', width: 1024, height: 768, lang: 'en', theme: 'light', scen: 'rich' },
  { tag: 'd-en', width: 1440, height: 900, lang: 'en', theme: 'light', scen: 'rich' },
  { tag: 'd-vi', width: 1440, height: 900, lang: 'vi', theme: 'light', scen: 'rich' },
  { tag: 'p-en-1', ...PHONE, lang: 'en', theme: 'light', scen: 'one' },
  { tag: 'd-en-1', width: 1440, height: 900, lang: 'en', theme: 'light', scen: 'one' },
  { tag: 'p-en-0', ...PHONE, lang: 'en', theme: 'light', scen: 'empty' },
  { tag: 'p-ov-rowmenu', ...PHONE, lang: 'en', theme: 'light', scen: 'rich', rowMenu: true },
]

/** Pages that are not a page of blocks, with the reason. */
const EXCEPTIONS: Record<string, string> = {}

/**
 * Pages that still join facts with " · " (the build line, the schema line and
 * the version badges on /health). Listed so the suite is green today; the
 * change that reworks that page removes its entry, and no entry may be added
 * for a page that is clean.
 */
const MIDDOT_PENDING = new Set(['/health'])

/** Console errors that are not a defect of the page: the browser's own resource notices. */
const IGNORED_CONSOLE = [/Failed to load resource/i]

function watchConsole(page: Page): string[] {
  const errors: string[] = []
  // The version check is read once per navigation: a trailing-slash key reads it twice (a redirect).
  let versionChecks = 0
  page.on('framenavigated', (f) => {
    if (f === page.mainFrame()) versionChecks = 0
  })
  page.on('request', (r) => {
    if (/\/api\/v1\/admin\/version-check\/?$/.test(new URL(r.url()).pathname)) versionChecks++
    if (versionChecks > 1)
      errors.push(`/version-check read ${versionChecks} times in one navigation`)
  })
  page.on('console', (m) => {
    if (m.type() === 'error' && !IGNORED_CONSOLE.some((re) => re.test(m.text()))) {
      errors.push(m.text())
    }
  })
  return errors
}

/**
 * Visible text nodes holding a separator the design bans: " · " anywhere, and
 * an em dash that is more than the lone empty-cell placeholder.
 */
async function separators(page: Page): Promise<{ middot: string[]; emDash: string[] }> {
  return page.evaluate(() => {
    const out = { middot: [] as string[], emDash: [] as string[] }
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const el = n.parentElement
      const text = (n.textContent ?? '').trim()
      if (!el || !text || el.closest('script,style,noscript')) continue
      const r = el.getBoundingClientRect()
      if (r.width === 0 || r.height === 0 || getComputedStyle(el).visibility === 'hidden') continue
      if (/\s·\s/.test(text)) out.middot.push(text.slice(0, 80))
      if (text.includes('—') && text !== '—') out.emDash.push(text.slice(0, 80))
    }
    return out
  })
}

async function checkPage(page: Page, route: string, consoleErrors: string[]) {
  await expect(page.locator('main h1').first()).toBeVisible({ timeout: 30_000 })
  for (const vp of VIEWPORTS) {
    await page.setViewportSize(vp)
    await page.waitForTimeout(300)
    const at = `${route} at ${vp.width}px`
    expect(await page.locator('h1:visible').count(), `${at}: one h1`).toBe(1)
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth
    )
    expect(overflow, `${at}: no horizontal scroll`).toBeLessThanOrEqual(0)
    expect(await wcagViolations(page), `${at}: axe WCAG 2.2 AA`).toEqual([])
    const sep = await separators(page)
    if (!MIDDOT_PENDING.has(route)) expect(sep.middot, `${at}: no " · "`).toEqual([])
    expect(sep.emDash, `${at}: no em dash (the lone empty-cell placeholder is allowed)`).toEqual([])
    // Every console table, raw ones included, follows the header rule.
    await checkAt(page, route, vp.width, [], { allTables: true })
  }
  expect(consoleErrors, `${route}: no console error`).toEqual([])
}

test.describe('console pages', () => {
  test.beforeAll(async ({ browser }) => {
    await ensureElevated(browser)
  })

  test('every page file is visited, every nav entry has a page', () => {
    const static_ = new Set(staticRoutes())
    for (const { title, url } of navRoutes()) {
      expect(static_.has(url), `nav entry "${title}" -> ${url} has no page.tsx`).toBe(true)
    }
    const listed = new Set(DETAIL_ROUTES.map((d) => d.route))
    for (const pattern of dynamicPatterns()) {
      expect(
        listed.has(pattern),
        `page ${pattern} is not in DETAIL_ROUTES (helpers/routes.ts)`
      ).toBe(true)
    }
    expect(pageRoutes().length).toBeGreaterThan(20)
  })

  for (const route of staticRoutes()) {
    if (route === '/login' || EXCEPTIONS[route]) continue
    test(`${route}`, async ({ page }) => {
      const errors = watchConsole(page)
      expect(await open(page, route), `${route} does not redirect`).toBe(true)
      await checkPage(page, route, errors)
    })
  }

  /**
   * The layout-break detectors of the tenant app's layout suite
   * (web/e2e/helpers/text-breaks.ts, spec 75) on the console lists whose
   * answers CONSOLE_LIST_DATA makes hard on the layout: 200, 1 and 0 rows,
   * long and Vietnamese names, at 390, 1024 and 1440, light and dark, en and
   * vi, and the row menu on a phone. A list is added here once it passes.
   */
  for (const route of Object.keys(CONSOLE_LIST_DATA)) {
    test(`${route} layout breaks`, async ({ page, baseURL }, testInfo) => {
      test.setTimeout(240_000)
      const found: string[] = []
      for (const v of BREAK_VARIANTS) {
        await page.unrouteAll({ behavior: 'ignoreErrors' })
        await page.setViewportSize({ width: v.width, height: v.height })
        await page.context().addCookies([
          { name: 'locale', value: v.lang, url: baseURL! },
          { name: 'theme', value: v.theme, url: baseURL! },
        ])
        await page.emulateMedia({ colorScheme: v.theme, reducedMotion: 'reduce' })
        await consoleListData(page, route, v.scen)
        await open(page, route)
        await expect(page.locator('main h1').first()).toBeVisible({ timeout: 30_000 })
        await page
          .locator('main [data-slot*="skeleton"], main [aria-busy="true"]')
          .first()
          .waitFor({ state: 'detached', timeout: 10_000 })
          .catch(() => undefined)
        await page.waitForTimeout(300)
        let scope = 'main'
        if (v.rowMenu) {
          const trigger = page
            .locator(
              'main [data-phone-card] button[aria-haspopup]:visible, main tbody tr button[aria-haspopup]:visible'
            )
            .first()
          if (!(await trigger.count())) continue
          await trigger.click()
          await page
            .locator('[role=menu]:visible, [data-slot="drawer-content"]:visible')
            .first()
            .waitFor()
          scope = '[role=menu], [data-slot="drawer-content"]'
        }
        const lines = formatBreaks(await findBreaks(page, { scope, vi: v.lang === 'vi' }))
        found.push(...lines.map((x) => `${v.tag}: ${x}`))
        // The picture of a variant that broke (every variant with
        // CONSOLE_LAYOUT_OUT, a folder for a review's screenshots).
        if (lines.length || LAYOUT_OUT) {
          const name = `${route.replace(/\W+/g, '-').replace(/^-|-$/g, '')}__${v.tag}.png`
          await page.screenshot({
            path: LAYOUT_OUT ? `${LAYOUT_OUT}/${name}` : testInfo.outputPath(name),
            fullPage: !v.rowMenu,
          })
        }
        if (v.rowMenu) await page.keyboard.press('Escape')
      }
      expect(found, `${route}: layout breaks`).toEqual([])
    })
  }

  for (const d of DETAIL_ROUTES) {
    test(`${d.route}`, async ({ page }) => {
      const errors = watchConsole(page)
      await page.goto('/')
      const id = await page.evaluate(
        async ({ url }) => {
          const res = await fetch(url, { credentials: 'same-origin' })
          if (!res.ok) return { error: `${url} answered ${res.status}` }
          const body = await res.json()
          const rows = body.data ?? body.items ?? body
          return { rows: Array.isArray(rows) ? rows : [] }
        },
        { url: d.list }
      )
      expect('error' in id ? id.error : '', 'the list that leads to the page loads').toBe('')
      const rows = (id as { rows: Record<string, unknown>[] }).rows
      expect(rows.length, `${d.list} has a row to open`).toBeGreaterThan(0)
      const route = d.route.replace('{id}', encodeURIComponent(String(d.id(rows[0]))))
      await open(page, route)
      await checkPage(page, route, errors)
    })
  }
})
