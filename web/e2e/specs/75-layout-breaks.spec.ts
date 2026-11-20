import fs from 'fs'
import path from 'path'
import type { Page, TestInfo } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import {
  BREAK_KINDS,
  findBreaks,
  formatBreaks,
  richData,
  type Breaks,
  type Scenario,
} from '../helpers/text-breaks'

/**
 * No text overlaps, no word broken inside, nothing cut without an ellipsis,
 * one control height per row, no English left in vi, no label without a
 * value and no row bunched at one side (a phone card with nothing at its end,
 * a title row line with an empty start), on every list and its main overlays,
 * with data that is hard on the layout (helpers/text-breaks.ts).
 *
 * Regression guarded (owner report 2026-11-19, /assets at 390 px, dark): a
 * system description ("IP address auto-created from DNS resolution") sat in
 * the card's type line; the line was told not to wrap, so the type label was
 * squeezed to "IP Addres / s" and the description ran under the Risk score.
 * The seed had no description, so every spec passed.
 *
 * Variants per route: 390x844 en and vi (light), 1440x900 and 1024x768 en; 0 and 1 rows at
 * 390 en; at 390 en the row menu, the filters sheet, the detail sheet and the
 * page's main dialog when the page has them.
 *
 * The full sweep (every route, dark theme, screenshots) runs the same spec:
 *   LAYOUT_SWEEP_ROUTES=<routes.json> LAYOUT_SWEEP_OUT=<dir> LAYOUT_SWEEP_FULL=1
 * routes.json: [{ "path": "/assets" }, ...]; findings land in <dir>/<slug>.json.
 */

type Variant = {
  tag: string
  width: number
  height: number
  lang: 'en' | 'vi'
  theme: 'light' | 'dark'
  scen: Scenario
  overlay?: Overlay
}
type Overlay = 'rowmenu' | 'filters' | 'detail' | 'dialog'

const PHONE = { width: 390, height: 844 }
const DESKTOP = { width: 1440, height: 900 }
const TABLET = { width: 1024, height: 768 }

/** Lists and pages with phone cards, sheets and long names. */
const CI_ROUTES = [
  '/assets',
  '/assets/groups',
  '/assets/changes',
  '/assets/duplicates',
  '/assets/suggestions',
  '/assets/attention/no-owner',
  '/assets/attention/unscanned',
  '/assets/attention/decide-monitoring',
  '/findings',
  '/findings/approvals',
  '/findings/ready-to-close',
  '/findings/imports',
  '/vulnerabilities',
  '/components',
  '/exposures',
  '/scans',
  '/scans/runs',
  '/scans/workflows',
  '/scans/approvals',
  '/sensors',
  '/my-work',
  '/attack-surface/exposures',
  '/attack-surface/technologies',
  '/remediation/tasks',
  '/settings/members',
  '/settings/audit-log',
  '/settings/api-keys',
  '/settings/scanning/scan-approval',
  '/notifications',
  '/oauth/device',
]

/**
 * Entry pages a person opens signed out (their own browser context, no
 * session): the form and the link-from-an-e-mail states the scratch stack can
 * reach without mail. Same checks, no list data or overlays.
 */
const SIGNED_OUT_ROUTES = [
  '/forgot-password',
  '/reset-password',
  '/reset-password#token=synthetic-reset-token',
  '/set-password#token=synthetic-setup-token',
  '/verify-email',
  '/request-access',
  '/request-access/confirm',
]

/**
 * Settings answers richData leaves alone (it skips /settings): the pages that
 * list records read from them get hard rows here, per scenario.
 */
function scanGovernance(scen: Scenario) {
  const rules = [
    {
      name: 'Crown jewels outside business hours on the production payment network and the gateways',
      conditions: {
        crown_jewel: true,
        hours: {
          match: 'outside',
          windows: [{ days: ['mon', 'tue', 'wed', 'thu', 'fri'], start: '09:00', end: '18:00' }],
        },
      },
      requirement: {
        approvals: 2,
        approver_roles: ['owner', 'admin'],
        require_justification: true,
      },
    },
    {
      name: 'Quét dải mạng rộng của chi nhánh Hà Nội và Thành phố Hồ Chí Minh ngoài giờ làm việc',
      monitor: true,
      conditions: { cidr_wider_than: 20, targets_over: 500, asset_tags: ['pci', 'prod'] },
      requirement: { approvals: 1, require_ticket: true, ticket_pattern: '^SEC-[0-9]+$' },
    },
    { name: 'x', enabled: false, conditions: {}, requirement: { approvals: 1 } },
  ].map((r, i) => ({ id: `00000000-0000-4000-8000-00000000000${i}`, enabled: true, ...r }))
  const n = scen === 'empty' ? 0 : scen === 'one' ? 1 : rules.length
  return {
    mode: 'on',
    source: 'organization',
    organization_mode: 'on',
    platform_policy: 'tenant_controlled',
    selectable_modes: ['off', 'on', 'strict'],
    scope_entries_need_approval: false,
    rules: rules.slice(0, n),
    pending_expiry_days: 7,
    presets: { light: [], standard: [], strict: [] },
  }
}
const ROUTE_DATA: Record<string, { url: string; body: (scen: Scenario) => unknown }> = {
  '/settings/scanning/scan-approval': {
    url: '**/api/v1/organization/settings/scan-governance',
    body: scanGovernance,
  },
}

/**
 * Lists whose phone cards (or title row) are still bunched at the start
 * (`lopsided`, owner report 2026-11-20), found when the check was added. Each
 * moves onto the phone card rule (state at the end of the title line, the
 * main action or a chevron at the end of the facts line) and leaves this
 * list; it only shrinks, and a route not on it fails on its first lopsided
 * row.
 */
const LOPSIDED_DEBT = new Set([
  '/findings', // one row: a title row line holds only its end controls
  '/findings/imports',
  '/scans/runs',
  '/attack-surface/technologies',
  '/settings/audit-log',
  '/remediation/tasks', // task cards stop at about half their width (seen once the seed has tasks)
])

const FULL = process.env.LAYOUT_SWEEP_FULL === '1'
const OUT = process.env.LAYOUT_SWEEP_OUT
const ROUTES: string[] = process.env.LAYOUT_SWEEP_ROUTES
  ? (
      JSON.parse(fs.readFileSync(process.env.LAYOUT_SWEEP_ROUTES, 'utf8')) as { path: string }[]
    ).map((r) => r.path)
  : CI_ROUTES

const OVERLAYS: Record<Overlay, string> = {
  rowmenu:
    'main [data-phone-card] button[aria-haspopup]:visible, main tbody tr button[aria-haspopup]:visible',
  filters:
    'main [data-slot="filter-panel-toggle"]:visible, main [data-slot="filter-button"]:visible, main [data-slot="add-filter"]:visible',
  detail: 'main [data-phone-card]:visible',
  dialog: 'main [data-slot="page-header"] button:not([aria-haspopup]):visible',
}

function variants(): Variant[] {
  const v: Variant[] = [
    { tag: 'p-en', ...PHONE, lang: 'en', theme: 'light', scen: 'rich' },
    { tag: 'p-vi', ...PHONE, lang: 'vi', theme: 'light', scen: 'rich' },
    { tag: 'd-en', ...DESKTOP, lang: 'en', theme: 'light', scen: 'rich' },
    { tag: 't-en', ...TABLET, lang: 'en', theme: 'light', scen: 'rich' },
    { tag: 'p-en-0', ...PHONE, lang: 'en', theme: 'light', scen: 'empty' },
    { tag: 'p-en-1', ...PHONE, lang: 'en', theme: 'light', scen: 'one' },
  ]
  if (FULL) {
    v.push(
      { tag: 'p-en-dark', ...PHONE, lang: 'en', theme: 'dark', scen: 'rich' },
      { tag: 'p-vi-dark', ...PHONE, lang: 'vi', theme: 'dark', scen: 'rich' },
      { tag: 'd-vi', ...DESKTOP, lang: 'vi', theme: 'light', scen: 'rich' }
    )
  }
  for (const overlay of Object.keys(OVERLAYS) as Overlay[]) {
    v.push({ tag: `p-ov-${overlay}`, ...PHONE, lang: 'en', theme: 'light', scen: 'rich', overlay })
    if (FULL) {
      v.push({
        tag: `d-ov-${overlay}`,
        ...DESKTOP,
        lang: 'en',
        theme: 'light',
        scen: 'rich',
        overlay,
      })
    }
  }
  return v
}

const slug = (route: string) => route.replace(/\W+/g, '-').replace(/^-|-$/g, '') || 'home'

async function prepare(page: Page, v: Variant, baseURL: string) {
  await page.setViewportSize({ width: v.width, height: v.height })
  await page.context().addCookies([
    { name: 'locale', value: v.lang, url: baseURL },
    { name: 'theme', value: v.theme, url: baseURL },
  ])
  await page.emulateMedia({ colorScheme: v.theme, reducedMotion: 'reduce' })
  await page.addInitScript((t) => {
    try {
      localStorage.setItem('theme', t)
    } catch {
      /* storage blocked: the cookie still sets the theme */
    }
  }, v.theme)
  await richData(page, v.scen)
}

async function settle(page: Page) {
  await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => {})
  // Loaded: main is drawn and no loading placeholder is left in it.
  await page
    .waitForFunction(
      () => {
        const main = document.querySelector('main')
        return (
          !!main &&
          main.getBoundingClientRect().height > 0 &&
          !main.querySelector(
            '[data-slot*="skeleton"], [class*="animate-pulse"], [aria-busy="true"]'
          )
        )
      },
      undefined,
      { timeout: 10_000 }
    )
    .catch(() => {})
  await page.waitForTimeout(300)
}

/** Opens the overlay; null when the page has none of that kind. */
async function openOverlay(page: Page, overlay: Overlay): Promise<string | null> {
  const trigger = page.locator(OVERLAYS[overlay]).first()
  if (!(await trigger.count())) return null
  await trigger.click({ timeout: 5_000 }).catch(() => {})
  const layer = page
    .locator(
      '[role=dialog]:visible, [role=menu]:visible, [data-slot="sheet-content"]:visible, [data-slot="drawer-content"]:visible'
    )
    .last()
  if (
    !(await layer
      .waitFor({ timeout: 5_000 })
      .then(() => true)
      .catch(() => false))
  )
    return null
  await page.waitForTimeout(400)
  return '[role=dialog], [role=menu], [data-slot="sheet-content"], [data-slot="drawer-content"]'
}

async function keep(testInfo: TestInfo, name: string, body: string | Buffer) {
  const file = OUT ? path.join(OUT, name) : testInfo.outputPath(name)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, body)
  if (!OUT) await testInfo.attach(name, { path: file })
}

test.describe('Layout breaks', { tag: ['@phone', '@shell'] }, () => {
  test.describe.configure({ mode: 'parallel' })
  for (const route of ROUTES) {
    test(`${route}`, async ({ page, baseURL }, testInfo) => {
      test.setTimeout(FULL ? 600_000 : 240_000)
      const report: Record<string, Breaks | string> = {}
      for (const v of variants()) {
        await page.unrouteAll({ behavior: 'ignoreErrors' })
        await prepare(page, v, baseURL!)
        const extra = ROUTE_DATA[route]
        if (extra) {
          await page.route(extra.url, (r) =>
            r.request().method() === 'GET' ? r.fulfill({ json: extra.body(v.scen) }) : r.fallback()
          )
        }
        await page.goto(route, { timeout: 60_000 }).catch(() => {})
        await settle(page)
        let scope = 'main'
        if (v.overlay) {
          const layer = await openOverlay(page, v.overlay)
          if (!layer) {
            report[v.tag] = 'no such overlay'
            continue
          }
          scope = layer
        }
        const found = await findBreaks(page, { scope, vi: v.lang === 'vi' })
        report[v.tag] = found
        if (OUT || formatBreaks(found).length) {
          await keep(testInfo, `${slug(route)}__${v.tag}.png`, await page.screenshot())
        }
        if (v.overlay) await page.keyboard.press('Escape').catch(() => {})
      }
      await keep(testInfo, `${slug(route)}.json`, JSON.stringify(report, null, 1))
      for (const [tag, found] of Object.entries(report)) {
        if (typeof found === 'string') continue
        for (const kind of BREAK_KINDS) {
          if (kind === 'lopsided' && LOPSIDED_DEBT.has(route)) continue
          expect.soft(found[kind], `${route} ${tag}: ${kind}`).toEqual([])
        }
      }
    })
  }
})

test.describe('Layout breaks, signed out', { tag: ['@phone', '@auth'] }, () => {
  test.describe.configure({ mode: 'parallel' })
  for (const route of process.env.LAYOUT_SWEEP_ROUTES ? [] : SIGNED_OUT_ROUTES) {
    test(`${route}`, async ({ browser, baseURL }, testInfo) => {
      test.setTimeout(120_000)
      const report: Record<string, Breaks> = {}
      for (const v of variants().filter((x) => !x.overlay && x.scen === 'rich')) {
        const context = await browser.newContext({ baseURL })
        const page = await context.newPage()
        await prepare(page, v, baseURL!)
        await page.goto(route, { timeout: 60_000 }).catch(() => {})
        await settle(page)
        report[v.tag] = await findBreaks(page, { scope: 'main', vi: v.lang === 'vi' })
        if (OUT || formatBreaks(report[v.tag]).length) {
          await keep(testInfo, `signed-out-${slug(route)}__${v.tag}.png`, await page.screenshot())
        }
        await context.close()
      }
      await keep(testInfo, `signed-out-${slug(route)}.json`, JSON.stringify(report, null, 1))
      for (const [tag, found] of Object.entries(report)) {
        for (const kind of BREAK_KINDS)
          expect.soft(found[kind], `${route} ${tag}: ${kind}`).toEqual([])
      }
    })
  }
})
