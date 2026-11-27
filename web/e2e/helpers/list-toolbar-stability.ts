import type { Page, Route as PlaywrightRoute } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Nothing in a list's header jumps (owner rule): on every list with the shared
 * title row and toolbar (Findings, Assets, Scans, Vulnerabilities, Emerging
 * threats, the attack surface's Exposures, Technologies and Certificates, Sensors
 * and Scan runs),
 * at 1440, 1280, 1024, 768 and 390 px, in English and Vietnamese, every
 * control of the toolbar row and of the title row keeps its box (0 px of
 * movement, 0 px of size change) through:
 * - the first load (the boxes as first painted against the boxes once the
 *   rows and the count have arrived; the list's requests are held back, the
 *   way a slow network does);
 * - a filter added, five more added (the chips row folds them into
 *   "+N more"), one removed, a grouping chosen;
 * - a quick view, a built-in view and a saved view opened, the saved view
 *   closed;
 * - the Basic | Query mode switched, a text the server refuses applied in
 *   Query mode and put right again, text typed in the field, the filters
 *   cleared;
 * - each value of the list's fixed scopes in turn (Findings: Practice and
 *   State);
 * - a column sorted, the density changed, a row selected (the bulk bar is an
 *   overlay), the row's drawer opened and closed;
 * - the second page opened (a test of its own: it needs more rows than one
 *   page holds, and is skipped when the seed has fewer).
 *
 * Allowed, and only these:
 * - the table moves down once when the chips row first appears, and back up
 *   when it goes, by exactly the row's height plus its gap;
 * - in Query mode the filter tokens (Add filter, Practice, State) step aside
 *   (not drawn, inert: checked) and the search field grows into their room;
 *   nothing else in the row moves;
 * - a refused query text says its problem in the status row under the
 *   toolbar: the table moves down by at most that row's height plus its gap
 *   (not at all beside a chips row that is already there), and back when the
 *   text is put right;
 * - the title row's start (view name, count, Modified, the Save view menu)
 *   follows the view's name and count; its buttons are checked never to
 *   disappear, and the title row's end (Refresh, Export, More) never moves;
 * - a changed view's Modified lozenge and its one Save view menu (Save view
 *   and Reset in it) (`list-modified`, `list-view-actions`) come with the
 *   first change and go
 *   with the last, in the row's start group: they move nothing else.
 *
 * Measured after the page settles (network idle, reduced motion, two frames).
 * Core lists run every width in both languages; the others run every width
 * in English and the widest and the phone width in Vietnamese.
 */

type Box = { x: number; y: number; w: number; h: number }
type Snap = {
  controls: Record<string, Box>
  titleEnd: Record<string, Box>
  titleStart: string[]
  listTop: number | null
  chipsRow: number | null
  /** Height of the query field's status row while it shows a problem. */
  statusRow: number | null
}

type ListSpec = {
  /** Up to six filters (URL params the list's chips show). */
  filters: readonly (readonly [string, string])[]
  /** The list groups from its toolbar. */
  group?: boolean
  /** The search has the Basic | Query switch. */
  query?: boolean
  /** The toolbar has a search field (default); `false` skips the typing steps. */
  search?: boolean
  /** Every width in both languages (the others: Vietnamese at 1440 and 390). */
  core?: boolean
  /** The list's own requests, held back for the first-load check. */
  data: RegExp
  /** Fixed scopes of the toolbar (URL params): every value in turn, then the default again. */
  scopes?: readonly { name: string; param: string; values: readonly string[] }[]
  /** The Views menu keeps saved views of this page; `query` is the view the test saves. */
  savedViews?: { page: string; query: string }
  /** Selecting a row shows the shared bulk bar. */
  bulkBar?: boolean
  /** A row opens an overlay on the list (not another page). */
  drawer?: boolean
  /** The list shows only once it has ever held a row (skipped on a seed without one). */
  optional?: boolean
}

const LISTS = {
  '/findings': {
    filters: [
      ['severity', 'critical'],
      ['priority_class', 'P0,P1'],
      ['source', 'pentest'],
      ['is_in_kev', 'true'],
      ['sla_status', 'overdue'],
      ['asset_crown_jewel', 'true'],
    ],
    group: true,
    query: true,
    core: true,
    data: /\/api\/v1\/findings/,
    scopes: [
      {
        name: 'Practice',
        param: 'practice',
        values: ['compliance', 'aspm', 'infra', 'external', 'cloud', 'offensive', 'all'],
      },
      { name: 'State', param: 'state', values: ['fixed', 'dispositioned', 'closed', 'all'] },
    ],
    savedViews: { page: 'findings', query: 'severity=critical&state=all' },
    bulkBar: true,
    drawer: true,
  },
  '/assets': {
    filters: [
      ['criticalities', 'high'],
      ['statuses', 'active'],
      ['environments', 'production'],
      ['has_owner', 'true'],
      ['internet_facing', 'true'],
      ['is_crown_jewel', 'true'],
    ],
    query: true,
    core: true,
    data: /\/api\/v1\/assets/,
    bulkBar: true,
    drawer: true,
  },
  '/scans': {
    filters: [
      ['status', 'active'],
      ['origin', 'system'],
    ],
    query: true,
    core: true,
    data: /\/api\/v1\/scan/,
    drawer: true,
  },
  '/vulnerabilities': {
    filters: [
      ['severity', 'critical'],
      ['priority_class', 'P0,P1'],
      ['kev', 'true'],
      ['exploit', 'true'],
      ['has_fix', 'true'],
      ['past_sla', 'true'],
    ],
    data: /\/api\/v1\/vulnerabilit/,
    scopes: [{ name: 'Findings', param: 'state', values: ['fixed', 'dispositioned', 'all'] }],
    savedViews: { page: 'vulnerabilities', query: 'severity=critical' },
    bulkBar: true,
  },
  // The CVE catalog tab: its own `cat_` params; search narrows the loaded
  // page, no query language.
  '/exposures/vulnerabilities?tab=catalog': {
    filters: [
      ['cat_kev', 'true'],
      ['cat_exploit', 'true'],
      ['cat_sev', 'critical,high'],
      ['cat_cvss', '7'],
      ['cat_epss', '0.1'],
    ],
    group: false,
    query: false,
    data: /\/api\/v1\/vulnerabilities$/,
  },
  '/emerging-threats': {
    filters: [
      ['level', 'immediate'],
      ['tier', 'confirmed'],
      ['kev', 'true'],
      ['exposure', 'internet'],
    ],
    data: /\/api\/v1\/emerging-threats/,
    scopes: [{ name: 'State', param: 'state', values: ['new', 'all'] }],
    drawer: true,
    optional: true,
  },
  '/attack-surface/exposures': {
    filters: [
      ['severity', 'critical'],
      ['primary', 'true'],
    ],
    data: /\/api\/v1\/(attack-surface|exposures)/,
    scopes: [
      { name: 'Status', param: 'state', values: ['all'] },
      { name: 'Asset monitoring', param: 'monitoring', values: ['all'] },
    ],
  },
  '/attack-surface/technologies': {
    filters: [
      ['category', 'web_server'],
      ['version', 'known'],
      ['cves', 'true'],
      ['kev', 'true'],
    ],
    data: /\/api\/v1\/attack-surface/,
  },
  '/attack-surface/certificates': {
    filters: [['status', 'expired']],
    data: /\/api\/v1\/attack-surface/,
  },
  // Searched on the page; no query language for sensors.
  '/sensors': {
    filters: [
      ['state', 'online'],
      ['role', 'scanner'],
      ['version', 'latest'],
      ['policy', 'enforced'],
      ['attention', '1'],
      ['exec', 'daemon'],
    ],
    group: false,
    query: false,
    data: /\/api\/v1\/sensors/,
  },
  // No search field and no Query mode: the run list takes field filters only.
  '/scans/runs': {
    filters: [
      ['kind', 'retest'],
      ['status', 'failed'],
      ['origin', 'all'],
    ],
    group: false,
    search: false,
    data: /\/api\/v1\/scan/,
  },
  // Credential leaks: three multi-value filters, no query language; the
  // grouping is a select of its own (not the Findings one).
  '/credentials': {
    filters: [
      ['severity', 'critical'],
      ['status', 'active'],
      ['source', 'data_breach'],
    ],
    group: false,
    query: false,
    data: /\/api\/v1\/credentials$/,
  },
  // Searched by name on the page; no query language for workflows.
  '/scans/workflows': {
    filters: [
      ['retired', 'show'],
      ['owner', 'mine'],
    ],
    group: false,
    query: false,
    data: /\/api\/v1\/scan-workflows/,
  },
} as const satisfies Record<string, ListSpec>

type Route = keyof typeof LISTS

const WIDTHS = [1440, 1280, 1024, 768, 390]

async function settle(page: Page) {
  await page.waitForLoadState('networkidle').catch(() => undefined)
  await page.evaluate(
    () => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r())))
  )
  await page.waitForTimeout(350)
}

async function snap(page: Page): Promise<Snap> {
  return page.evaluate(() => {
    const shown = (el: Element | null | undefined): el is HTMLElement =>
      !!el && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden'
    const main = document.querySelector('main')!
    // Page coordinates: typing in a field below the fold scrolls the page to
    // it, which moves nothing in the layout (a phone list under a tall strip).
    let scrolled = window.scrollY
    for (let el: Element | null = main; el; el = el.parentElement) scrolled += el.scrollTop
    const box = (el: Element): { x: number; y: number; w: number; h: number } => {
      const r = el.getBoundingClientRect()
      return {
        x: Math.round(r.x),
        y: Math.round(r.y + scrolled),
        w: Math.round(r.width),
        h: Math.round(r.height),
      }
    }
    const toolbar = main.querySelector('[data-slot="list-toolbar"]')!
    const region =
      toolbar.closest('[data-slot="list-toolbar-region"], [data-slot="list-toolbar-frame"]') ??
      toolbar
    const controls: Record<string, Box> = {}
    const mode = Array.from(toolbar.querySelectorAll('[data-slot="list-search-mode"]')).find(shown)
    if (mode) controls['mode switch'] = box(mode)
    const field = toolbar.querySelector('[data-slot="list-search"]')
    if (shown(field)) controls['search field'] = box(field)
    Array.from(toolbar.querySelectorAll('[data-slot="list-toolbar-tokens"] > *'))
      .filter(shown)
      .forEach((el, i) => {
        controls[`token ${i + 1}`] = box(el)
      })
    Array.from(toolbar.querySelectorAll('[data-slot="list-toolbar-end"] > *'))
      .filter(shown)
      .forEach((el, i) => {
        controls[`end ${i + 1}`] = box(el)
      })
    // The title row: the buttons above the toolbar in the list's own header.
    const top = region.getBoundingClientRect().top
    const head = Array.from(main.querySelectorAll('button')).filter(
      (b) =>
        shown(b) &&
        b.getBoundingClientRect().bottom <= top &&
        !b.closest('[data-slot="list-toolbar-region"], [data-slot="list-toolbar"], nav, header')
    )
    const name = (b: HTMLElement) =>
      // A metric tile by its label: its count and detail line arrive after it.
      // Without numbers otherwise: a count arrives after its label.
      (
        b.querySelector('[data-slot="metric-label"]')?.textContent ||
        b.getAttribute('aria-label') ||
        b.textContent ||
        ''
      )
        .replace(/\d[\d,.]*\+?/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
    const mid = main.getBoundingClientRect().left + main.getBoundingClientRect().width / 2
    const titleEnd: Record<string, Box> = {}
    const titleStart: string[] = []
    for (const b of head) {
      // A changed view's own buttons come and go with the change.
      if (b.closest('[data-slot="list-view-actions"]')) continue
      // The shared title row names its groups; elsewhere, by the half it is in.
      const atEnd = b.closest('[data-slot="list-title-end"]')
        ? true
        : b.closest('[data-slot="list-title-start"]')
          ? false
          : b.getBoundingClientRect().left >= mid
      if (atEnd) titleEnd[name(b)] = box(b)
      else titleStart.push(name(b))
    }
    // What follows the toolbar (with its chips row): the table or the cards.
    let listTop: number | null = null
    let el: Element | null = region
    while (el && listTop === null) {
      for (let n = el.nextElementSibling; n; n = n.nextElementSibling) {
        const r = n.getBoundingClientRect()
        if (r.height > 0 && getComputedStyle(n).display !== 'none') {
          listTop = Math.round(r.top + scrolled)
          break
        }
      }
      el = el.parentElement
    }
    const chips = Array.from(
      region.querySelectorAll('[data-slot="list-toolbar-below"], [data-slot="filter-chips-row"]')
    ).find((c) => shown(c) && c.getBoundingClientRect().height > 0)
    const status = region.querySelector('[data-slot="list-toolbar-status"][data-drawn]')
    return {
      controls,
      titleEnd,
      titleStart,
      listTop,
      chipsRow: chips ? Math.round(chips.getBoundingClientRect().height) : null,
      statusRow: shown(status) ? Math.round(status.getBoundingClientRect().height) : null,
    }
  })
}

function compare(step: string, a: Snap, b: Snap, modeSwitch: false | 'phone' | 'wide' = false) {
  const problems: string[] = []
  // Query mode: the tokens step aside and the field grows into their room. On
  // a phone the Query field takes the whole first line: the end actions step
  // down one row too (44 px, the list with them). Nothing else moves.
  const ROW = 44
  const phoneModeSwitch = modeSwitch === 'phone'
  const stepsDown = (k: string) =>
    (!!modeSwitch && (k === 'search field' || k.startsWith('token'))) ||
    (phoneModeSwitch && k.startsWith('end'))
  // On a phone the tokens that filter are drawn on lines below the Query field
  // and wrap: a token may come or go, and the list moves with the lowest edge of
  // the field and its tokens, plus the chips row that came, went or wrapped.
  const belowField = (s: Snap) => {
    const field = s.controls['search field']
    return Object.entries(s.controls).filter(
      ([k, v]) => k.startsWith('token') && field && v.y > field.y
    )
  }
  const stackEdge = (s: Snap) => {
    const field = s.controls['search field']
    return Math.max(field ? field.y + field.h : 0, ...belowField(s).map(([, v]) => v.y + v.h))
  }
  const chipsPart = (s: Snap) => (s.chipsRow === null ? 0 : s.chipsRow + 8)
  const tokensWrap = belowField(a).length > 0 || belowField(b).length > 0
  for (const [k, v] of Object.entries(a.controls)) {
    if (stepsDown(k)) continue
    // Wrapped tokens flow: one that goes shifts the ones after it up a place.
    if (tokensWrap && k.startsWith('token')) continue
    const w = b.controls[k]
    if (!w) {
      problems.push(`${k} disappeared`)
      continue
    }
    if (v.x !== w.x || v.y !== w.y) problems.push(`${k} moved ${w.x - v.x},${w.y - v.y}`)
    if (v.w !== w.w || v.h !== w.h) problems.push(`${k} resized ${w.w - v.w}x${w.h - v.h}`)
  }
  for (const k of Object.keys(b.controls)) {
    if (!a.controls[k] && !stepsDown(k) && !(tokensWrap && k.startsWith('token')))
      problems.push(`${k} appeared`)
  }
  for (const [k, v] of Object.entries(a.titleEnd)) {
    const w = b.titleEnd[k]
    if (!w) problems.push(`title-row "${k}" disappeared`)
    else if (v.x !== w.x || v.y !== w.y || v.w !== w.w || v.h !== w.h)
      problems.push(`title-row "${k}" moved or resized`)
  }
  for (const k of a.titleStart) {
    if (!b.titleStart.includes(k)) problems.push(`title-row "${k}" disappeared`)
  }
  if (a.listTop !== null && b.listTop !== null && a.listTop !== b.listTop) {
    const rowCame = a.chipsRow === null && b.chipsRow !== null
    const rowWent = a.chipsRow !== null && b.chipsRow === null
    const step = (b.chipsRow ?? a.chipsRow ?? 0) + 8
    // The status row of a refused query text: one row step, or none beside a
    // chips row that is already there.
    const statusCame = a.statusRow === null && b.statusRow !== null
    const statusWent = a.statusRow !== null && b.statusRow === null
    const statusStep = (b.statusRow ?? a.statusRow ?? 0) + 8
    const delta = b.listTop - a.listTop
    // A phone wraps its chips onto more lines: a chips row that was already
    // there grows by whole lines and the list moves with it, by exactly that.
    const rowGrew = a.chipsRow !== null && b.chipsRow !== null && delta === b.chipsRow - a.chipsRow
    const tokensGrew =
      tokensWrap && delta === stackEdge(b) - stackEdge(a) + chipsPart(b) - chipsPart(a)
    if (!(
      rowGrew ||
      tokensGrew ||
      (phoneModeSwitch && Math.abs(delta) === ROW) ||
      (rowCame && delta === step) ||
      (rowWent && delta === -step) ||
      (statusCame && delta === statusStep) ||
      (statusWent && delta === -statusStep)
    ))
      problems.push(`list top moved ${delta}`)
  }
  expect(problems, `${step}: ${JSON.stringify({ before: a, after: b })}`).toEqual([])
}

async function setUrl(page: Page, search: URLSearchParams) {
  await page.evaluate((qs) => {
    const url = `${window.location.pathname}${qs ? `?${qs}` : ''}`
    window.history.replaceState(window.history.state, '', url)
  }, search.toString())
  await settle(page)
}

/** The route's own query (a tab such as `?tab=catalog`): a reset keeps it. */
function routeParams(route: string) {
  return new URLSearchParams(route.split('?')[1] ?? '')
}

/** Back to the top: a click on a row or on the pager may have scrolled the page. */
async function toTop(page: Page) {
  await page.evaluate(() => {
    let el: Element | null = document.querySelector('main [data-slot="list-toolbar"]')
    for (; el; el = el.parentElement) {
      el.scrollTop = 0
      el.scrollLeft = 0
    }
    window.scrollTo(0, 0)
  })
}

/** The page's current query string, as params. */
async function urlParams(page: Page) {
  return new URLSearchParams(await page.evaluate(() => window.location.search))
}

/** Holds the list's own requests back, the way a slow network does. Returns the release. */
async function holdBack(page: Page, data: RegExp) {
  const matches = (url: URL) => data.test(url.pathname)
  const late = async (route: PlaywrightRoute) => {
    await new Promise((r) => setTimeout(r, 600))
    await route.continue().catch(() => undefined)
  }
  await page.route(matches, late)
  return () => page.unroute(matches, late)
}

type FirstPaint = { title: Box | null; titleEnd: Box[]; header: Snap | null }

/**
 * What the header shows before the rows arrive: the title row's box, the
 * boxes of its end buttons and, where the toolbar is drawn already, the
 * whole snapshot.
 */
/** What shows once a list's toolbar is drawn: its search field, or the toolbar without one. */
function toolbarShown(list: ListSpec): string {
  return list.search === false
    ? 'main [data-slot="list-toolbar"]'
    : 'main [data-slot="list-toolbar"] [data-slot="list-search-input"]'
}

async function firstPaint(page: Page, shownSelector: string): Promise<FirstPaint> {
  const frame = await page.evaluate(() => {
    const box = (el: Element) => {
      const r = el.getBoundingClientRect()
      return {
        x: Math.round(r.x),
        y: Math.round(r.y),
        w: Math.round(r.width),
        h: Math.round(r.height),
      }
    }
    const row = document.querySelector('main [data-slot="list-title-row"]')
    return {
      title: row && row.getClientRects().length > 0 ? box(row) : null,
      titleEnd: Array.from(row?.querySelectorAll('[data-slot="list-title-end"] button') ?? [])
        .filter((b) => b.getClientRects().length > 0)
        .map(box),
    }
  })
  const drawn = await page
    .locator(shownSelector)
    .first()
    .isVisible()
    .catch(() => false)
  // An optional list may swap its toolbar for its empty page right now: no
  // header then (the caller skips such a list once it has settled).
  return { ...frame, header: drawn ? await snap(page).catch(() => null) : null }
}

function compareFirstPaint(step: string, a: FirstPaint, b: FirstPaint) {
  const same = (v: Box, w: Box | undefined) =>
    !!w && v.x === w.x && v.y === w.y && v.w === w.w && v.h === w.h
  const problems: string[] = []
  if (a.title && !same(a.title, b.title ?? undefined)) problems.push('the title row moved')
  a.titleEnd.forEach((v, i) => {
    if (!same(v, b.titleEnd[i])) problems.push(`title-row end button ${i + 1} moved`)
  })
  expect(problems, `${step}: ${JSON.stringify({ before: a, after: b })}`).toEqual([])
  if (a.header && b.header) compare(step, a.header, b.header)
}

/** A same-origin API call as the signed-in person (the page's own session and CSRF pair). */
async function api(page: Page, method: string, path: string, body?: unknown) {
  return page.evaluate(
    async ({ method, path, body }) => {
      const csrf = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/)?.[1] ?? ''
      const res = await fetch(path, {
        method,
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf) },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
      const text = await res.text()
      let json: unknown = null
      try {
        json = JSON.parse(text)
      } catch {
        // Not JSON (an empty 204): the status says enough.
      }
      return { status: res.status, json, text: text.slice(0, 300) }
    },
    { method, path, body }
  )
}

const SAVED_VIEW_PREFIX = 'E2E header stability'

/**
 * A personal saved view of the seed user for the test, and what an earlier,
 * interrupted run left behind (older than ten minutes: a parallel worker's
 * view is in use).
 */
async function createSavedView(page: Page, spec: { page: string; query: string }, tag: string) {
  const listed = await api(page, 'GET', `/api/v1/views?page=${spec.page}`)
  const stale = (
    (
      listed.json as {
        data?: { id: string; name: string; is_owner: boolean; created_at: string }[]
      }
    )?.data ?? []
  ).filter(
    (v) =>
      v.is_owner &&
      v.name.startsWith(SAVED_VIEW_PREFIX) &&
      Date.now() - Date.parse(v.created_at) > 10 * 60_000
  )
  for (const v of stale) await api(page, 'DELETE', `/api/v1/views/${encodeURIComponent(v.id)}`)
  const name = `${SAVED_VIEW_PREFIX} ${tag} ${Date.now()}`
  const made = await api(page, 'POST', '/api/v1/views', { ...spec, name })
  const id = (made.json as { id?: string } | null)?.id
  expect(id, `saved view created (${made.status}): ${made.text}`).toBeTruthy()
  return { id: id!, name }
}

/**
 * Opens the list and waits for its toolbar; false when the page shows no list
 * once it has loaded (a list that shows only after it has held a row draws
 * its toolbar while it loads, then its empty page).
 */
async function openList(
  page: Page,
  path: string,
  timeout = 45_000,
  shownSelector = 'main [data-slot="list-search-input"]'
) {
  await page.goto(path)
  const input = page.locator(shownSelector).first()
  const drawn = await input.waitFor({ state: 'visible', timeout }).then(
    () => true,
    () => false
  )
  if (!drawn) return false
  await settle(page)
  return input.isVisible()
}

const NO_LIST = 'the list shows only once it has held a row: the seed has none'

/**
 * Known movement, each with its owner and a request in the UI v2 list-family
 * notes. A case listed here is fixme until its owner lands the fix; remove
 * the entry with that fix.
 */
function knownMovement(route: Route, width: number, locale: 'en' | 'vi'): string | null {
  if (route === '/scans' && width === 390 && locale === 'vi')
    return 'scans page (scans list owner): on first load in Vietnamese the first token narrows by 2 px when the rows arrive'
  if (route === '/assets' && width === 1440 && locale === 'vi')
    return 'assets page (assets list owner): on first load in Vietnamese the title-row end buttons move when the count arrives'
  return null
}

export function headerHoldsStill(route: Route) {
  const list: ListSpec = LISTS[route]
  for (const locale of ['en', 'vi'] as const) {
    for (const width of WIDTHS) {
      if (!list.core && locale === 'vi' && width !== 1440 && width !== 390) continue
      test(`${route} header holds still at ${width}px ${locale}`, async ({ page, baseURL }) => {
        test.setTimeout(300_000)
        const known = knownMovement(route, width, locale)
        test.fixme(!!known, known ?? '')
        await page.emulateMedia({ reducedMotion: 'reduce' })
        await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
        await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })

        // A saved view of the test's own, made before the list is opened: the
        // page reads the saved views once and keeps them.
        let saved: { id: string; name: string } | null = null
        if (list.savedViews) {
          await page.goto(route)
          await page.locator('main').first().waitFor({ state: 'visible', timeout: 45_000 })
          saved = await createSavedView(page, list.savedViews, `${width} ${locale}`)
        }
        try {
          // The first load: what is painted before the rows arrive stays put.
          const release = await holdBack(page, list.data)
          await page.goto(route)
          await page
            .locator('main [data-slot="list-title-row"], main [data-slot="list-toolbar-region"]')
            .first()
            .waitFor({ state: 'visible', timeout: 45_000 })
            .catch(() => undefined)
          const painted = await firstPaint(page, toolbarShown(list))
          const input = page.locator(toolbarShown(list)).first()
          const drawn = await input
            .waitFor({ state: 'visible', timeout: list.optional ? 15_000 : 45_000 })
            .then(
              () => true,
              () => false
            )
          await release()
          if (drawn) await settle(page)
          const shown = drawn && (await input.isVisible())
          test.skip(!!list.optional && !shown, NO_LIST)
          expect(shown, 'the list toolbar shows').toBe(true)
          compareFirstPaint(
            `${route} ${width} ${locale}: first load`,
            painted,
            await firstPaint(page, toolbarShown(list))
          )

          const params = await urlParams(page)
          const sync = async () => {
            for (const k of [...params.keys()]) params.delete(k)
            ;(await urlParams(page)).forEach((v, k) => params.set(k, v))
          }
          let last = await snap(page)
          const step = async (name: string, act: () => Promise<void>) => {
            await act()
            await settle(page)
            const now = await snap(page)
            compare(
              `${route} ${width} ${locale}: ${name}`,
              last,
              now,
              /^switch (to Query|back to Basic)/.test(name) && (width < 448 ? 'phone' : 'wide')
            )
            last = now
          }

          // A filter, then five more (overflow), then one removed.
          const [first, ...more] = list.filters
          await step('add a filter', async () => {
            params.set(first[0], first[1])
            await setUrl(page, params)
          })
          await step('add five more', async () => {
            for (const [k, v] of more) params.set(k, v)
            await setUrl(page, params)
          })
          await step('remove one', async () => {
            params.delete(more[more.length - 1]?.[0] ?? first[0])
            await setUrl(page, params)
          })

          // Group (where the list groups from its toolbar).
          const group = page.getByRole('combobox', { name: /^(group findings|nhóm phát hiện)/i })
          if (list.group && (await group.isVisible())) {
            await step('choose a group', async () => {
              await group.click()
              await page.getByRole('option').nth(1).click()
            })
          }

          // A view: a quick view of the list in the sidebar, then the first
          // built-in view of the Views menu, then a saved view.
          const quick = page.locator(`[data-slot="sidebar"] a[href^="${route}?"]:visible`).nth(1)
          if (await quick.isVisible().catch(() => false)) {
            await step('open a quick view', async () => {
              await quick.click()
              await page.waitForURL((u) => u.search !== `?${params.toString()}`)
            })
            await sync()
          }
          const views = page.getByTestId('saved-views-trigger')
          if (await views.isVisible()) {
            await views.click()
            const item = page.getByRole('menuitemcheckbox').first()
            if (await item.isVisible().catch(() => false)) {
              await step('choose a view', async () => {
                await item.click()
                await page.keyboard.press('Escape')
              })
            } else {
              await page.keyboard.press('Escape')
            }
            await sync()
            if (saved) {
              await step('open a saved view', async () => {
                // The menu before it may still be closing: open until the item shows.
                const item = page.getByRole('menuitem').filter({ hasText: saved.name }).first()
                // Open it only while the trigger says it is closed (a second
                // click on an opening menu closes it), then choose the item.
                await expect(async () => {
                  if ((await views.getAttribute('aria-expanded')) !== 'true') await views.click()
                  await expect(item).toBeVisible({ timeout: 5_000 })
                  await item.click({ timeout: 5_000 })
                }).toPass({ timeout: 30_000 })
                await page.waitForURL((u) => u.searchParams.get('view') === saved.id)
              })
              await step('close the saved view', async () => {
                await views.click()
                await page.getByRole('menuitem', { name: /^(clear view|bỏ chế độ xem)$/i }).click()
                await page.waitForURL((u) => u.searchParams.get('view') !== saved.id)
              })
              await sync()
            }
          }

          // Basic | Query and back.
          if (list.query) {
            const toQuery = page.locator(
              'main [data-slot="list-search-mode-query"]:visible, main button[data-slot="list-search-mode"]:visible'
            )
            await step('switch to Query mode', async () => {
              await toQuery.click()
              await page
                .locator('main [data-slot="list-search-query"] [role="combobox"]')
                .waitFor({ state: 'visible', timeout: 20_000 })
              await page.locator('main h1').first().click({ force: true })
            })
            // The tokens step aside, inert: the text owns the filter.
            const tokens = page.locator('main [data-slot="list-toolbar-tokens"]')
            if ((await tokens.count()) > 0) {
              await expect(tokens.first()).toHaveAttribute('inert', '')
              await expect(tokens.first()).toBeHidden()
            }

            // A text the server refuses: its problem shows in the status row
            // under the toolbar, one row high, and the toolbar row keeps its
            // height; putting the text right takes the row away again.
            const editor = page.locator('main [data-slot="list-search-query"] [role="combobox"]')
            const statusRow = page.locator('main [data-slot="list-toolbar-status"]')
            const appliedText = await editor.inputValue()
            await step('apply a text the server refuses', async () => {
              // One character of value: no value lookup opens a list over Enter.
              await editor.fill('no_such_field=1')
              await editor.press('Enter')
              await expect(statusRow).toHaveAttribute('data-drawn', '', { timeout: 20_000 })
              await expect(editor).toHaveAttribute('aria-invalid', 'true')
            })
            {
              // The problem line is the one the field is described by, inside the
              // status row, as tall as a chips row (32, 36 on a phone).
              const line = statusRow.locator('[data-slot="query-status"]')
              await expect(line).toBeVisible()
              expect(await editor.getAttribute('aria-describedby')).toBe(
                await line.getAttribute('id')
              )
              await expect(line).toHaveAttribute('aria-live', 'polite')
              const h = (await statusRow.boundingBox())!.height
              expect(Math.round(h)).toBe(width < 768 ? 36 : 32)
              const main = (await page.locator('main').boundingBox())!
              const sb = (await statusRow.boundingBox())!
              expect(sb.x + sb.width).toBeLessThanOrEqual(main.x + main.width + 0.5)
            }
            await step('put the text right', async () => {
              await editor.fill(appliedText)
              await expect(statusRow).not.toHaveAttribute('data-drawn', '')
              await expect(editor).toHaveAttribute('aria-invalid', 'false')
              await page.locator('main h1').first().click({ force: true })
            })
            const toBasic = page.locator(
              'main [data-slot="list-search-mode-basic"]:visible, main button[data-slot="list-search-mode"]:visible'
            )
            await step('switch back to Basic', async () => {
              await toBasic.click()
              await page
                .locator('main [data-slot="list-search-input"]')
                .waitFor({ state: 'visible', timeout: 20_000 })
            })
          }

          if (list.search !== false) {
            await step('type in the field', async () => {
              await page.locator('main [data-slot="list-search-input"]').fill('zz-no-match')
            })
            await step('clear the text', async () => {
              await page.locator('main [data-slot="list-search-input"]').fill('')
            })
          }

          await step('clear the filters', async () => {
            const clear = page.locator('main [data-slot="filter-chips-clear"]:visible')
            if (await clear.isVisible()) await clear.click()
            else await setUrl(page, routeParams(route))
          })

          // The list as it opens (no grouping, no view), for the row steps.
          await step('back to the list as it opens', async () => {
            await setUrl(page, routeParams(route))
          })
          await sync()

          // The fixed scopes: every value in turn, then the default again.
          for (const scope of list.scopes ?? []) {
            for (const value of scope.values) {
              await step(`${scope.name}: ${value}`, async () => {
                params.set(scope.param, value)
                await setUrl(page, params)
              })
            }
            await step(`${scope.name}: the default again`, async () => {
              params.delete(scope.param)
              await setUrl(page, params)
            })
          }

          // Sort by the first sortable column (a table; phone cards have no header).
          const sort = page
            .locator('main [data-slot="table-container"] [data-slot="sort-button"]:visible')
            .first()
          if (await sort.isVisible().catch(() => false)) {
            await step('sort a column', async () => {
              await sort.click()
              await toTop(page)
            })
          }

          // Density, from the Display menu (hidden where the list shows cards).
          const display = page
            .locator('main [data-slot="list-toolbar-end"]')
            .getByRole('button', { name: /^(display: density|hiển thị: mật độ)/i })
          if (await display.isVisible().catch(() => false)) {
            const radios = page.getByRole('menuitemradio')
            await display.click()
            await radios.first().waitFor({ state: 'visible', timeout: 10_000 })
            const states = await radios.evaluateAll((els) =>
              els.map((el) => el.getAttribute('aria-checked') === 'true')
            )
            const was = Math.max(0, states.indexOf(true))
            const other = was === 0 ? 1 : 0
            await step('change the density', async () => {
              await radios.nth(other).click()
            })
            await step('the density as it was', async () => {
              await display.click()
              await radios.nth(was).click()
            })
          }

          // Select a row: the bulk bar is an overlay, nothing above the rows moves.
          const rows = page.locator(
            'main [data-slot="table-container"] tbody tr:has(td:nth-child(2)):visible'
          )
          const box = rows.first().getByRole('checkbox').first()
          if (await box.isVisible().catch(() => false)) {
            await step('select a row', async () => {
              await box.click()
              if (list.bulkBar)
                await expect(page.locator('[data-slot="bulk-action-bar"]')).toBeVisible()
              await toTop(page)
            })
            await step('clear the selection', async () => {
              await box.click()
              await toTop(page)
            })
          }

          // The row's drawer (an overlay on the list), opened and closed.
          const row = rows.or(page.locator('main [data-slot="mobile-card"]:visible')).first()
          if (list.drawer && (await row.isVisible().catch(() => false))) {
            const drawer = page.getByRole('dialog').first()
            // The row's own corner: not its checkbox, link or menu.
            await row.click({ position: { x: 3, y: 3 } })
            const opened = await drawer.waitFor({ state: 'visible', timeout: 15_000 }).then(
              () => true,
              () => false
            )
            expect(opened, `${route} ${width} ${locale}: a row opens its drawer`).toBe(true)
            await step('open the drawer', async () => {
              await toTop(page)
            })
            await step('close the drawer', async () => {
              await page.keyboard.press('Escape')
              await drawer.waitFor({ state: 'hidden', timeout: 15_000 })
              await toTop(page)
            })
          }
        } finally {
          if (saved)
            await api(page, 'DELETE', `/api/v1/views/${encodeURIComponent(saved.id)}`).catch(
              () => undefined
            )
        }
      })
    }
  }
}

/**
 * The second page (data-dependent: the list must hold more rows than one
 * page shows; the seed gives Findings 26, see `e2e/ci/seed.sh`). The pager is
 * under the rows: going to page 2 and back moves nothing above them.
 */
export function pagingHoldsStill(route: Route) {
  const list: ListSpec = LISTS[route]
  for (const width of [1440, 390]) {
    test(`${route} header holds still on page 2 at ${width}px`, async ({ page }) => {
      test.setTimeout(120_000)
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
      const shown = await openList(page, route, list.optional ? 15_000 : 45_000, toolbarShown(list))
      test.skip(!!list.optional && !shown, NO_LIST)
      expect(shown, 'the list toolbar shows').toBe(true)
      await settle(page)
      const pager = page.locator('main [data-slot="data-table-pager"]')
      const next = pager.getByRole('button', { name: 'Next page', exact: true })
      const more = (await next.isVisible().catch(() => false)) && (await next.isEnabled())
      test.skip(!more, 'page 2 needs more rows than one page holds: the seed has fewer here')
      const before = await snap(page)
      await next.click()
      await settle(page)
      await toTop(page)
      const second = await snap(page)
      compare(`${route} ${width}: page 2`, before, second)
      await pager.getByRole('button', { name: 'Previous page', exact: true }).click()
      await settle(page)
      await toTop(page)
      compare(`${route} ${width}: page 1 again`, second, await snap(page))
    })
  }
}

/**
 * A changed view (owner rule): the title keeps a real view's name, and right
 * after the count come the Modified lozenge (20 px with its dashed border)
 * and one Save view menu button (Save view and Reset in it). On a row under
 * 42rem and on a phone the menu's items are in the row's More and only the
 * lozenge stays. The end group (Refresh, Export, Task or More) keeps its
 * boxes when they come and when they go, the view's name is never cut on a
 * changed view (1024 px vi cut "Đang hoạt động" to "Đan…", 2026-11-26), and
 * Reset returns to the exact base view.
 */
export function changedViewSaysSo() {
  for (const [width, locale] of [
    [1440, 'en'],
    [1024, 'en'],
    [1024, 'vi'],
    [390, 'en'],
  ] as const) {
    test(`/findings a changed view shows Modified and one Save view menu at ${width}px ${locale}`, async ({
      page,
      baseURL,
    }) => {
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
      await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
      await page.goto('/findings')
      const row = page.getByTestId('findings-toolbar-primary')
      await expect(row).toBeVisible({ timeout: 45_000 })
      await expect(row.locator('[data-slot="list-count"]')).toHaveText(/\d/, { timeout: 45_000 })
      await settle(page)
      const title = page.getByTestId('findings-view-title')
      const baseName = (await title.innerText()).trim()
      const baseUrl = await page.evaluate(() => window.location.search)
      const modified = row.locator('[data-slot="list-modified"]')
      const save = row.locator('[data-slot="list-view-save"]')
      await expect(modified).toHaveCount(0)
      await expect(save).toHaveCount(0)
      const before = await snap(page)

      const params = new URLSearchParams(baseUrl)
      params.set('severity', 'critical')
      await setUrl(page, params)
      await expect(modified).toBeVisible()
      await expect(title).toHaveText(baseName)
      await expect(title).not.toHaveText(/custom view|saved view/i)
      const changed = await snap(page)
      compare(`/findings ${width} ${locale}: a filter added`, before, changed)
      // The name is read whole beside Modified and the menu (from a tablet up).
      if (width >= 768) {
        const cut = await title.evaluate((el) => el.scrollWidth > el.clientWidth + 1)
        expect(cut, `view name "${baseName}" cut at ${width}px ${locale}`).toBe(false)
      }

      // The pill and the lozenge are 20 px; the count's tooltip names the scope.
      const count = row.locator('[data-slot="list-count"]')
      expect(Math.round((await count.boundingBox())!.height)).toBe(20)
      expect(Math.round((await modified.boundingBox())!.height)).toBe(20)
      if (locale === 'en') await expect(count).toHaveAttribute('title', /data scope/i)
      // Order in the start group: count, Modified, then the one menu button.
      const order = await row.evaluate((el) =>
        Array.from(
          el.querySelectorAll(
            '[data-slot="list-count"], [data-slot="list-modified"], [data-slot="list-view-save"], [data-slot="list-view-reset"]'
          )
        )
          .filter((n) => n.getClientRects().length > 0)
          .map((n) => ({ slot: n.getAttribute('data-slot'), x: n.getBoundingClientRect().x }))
      )
      expect(order.map((o) => o.slot).slice(0, 2)).toEqual(['list-count', 'list-modified'])
      expect(order.map((o) => o.slot)).not.toContain('list-view-reset')
      expect([...order].sort((a, b) => a.x - b.x)).toEqual(order)
      // Nothing in the row is drawn over its neighbour or past the row.
      const overlap = await row.evaluate((el) => {
        const kids = Array.from(
          el.querySelectorAll(
            '[data-slot="list-title-start"] > *, [data-slot="list-title-end"] > *'
          )
        )
          .filter((n) => n.getClientRects().length > 0)
          .map((n) => n.getBoundingClientRect())
        const r = el.getBoundingClientRect()
        return kids.some(
          (a, i) =>
            a.right > r.right + 1 ||
            kids.some((b, j) => j > i && a.right > b.left + 1 && b.right > a.left + 1)
        )
      })
      expect(overlap, 'title row parts overlap or leave the row').toBe(false)

      const words =
        locale === 'en'
          ? { save: 'Save view', reset: 'Reset' }
          : { save: 'Lưu chế độ xem', reset: 'Đặt lại' }
      const menu = page.getByRole('menu').or(page.getByRole('dialog'))
      const rowWidth = (await row.boundingBox())!.width
      if (rowWidth >= 672) {
        await expect(save).toBeVisible()
        await save.click()
      } else {
        // Folded: only the lozenge stays; the row's More holds the items.
        expect(locale, 'the folded row is checked in English').toBe('en')
        await expect(save).toBeHidden()
        await row.getByRole('button', { name: 'More actions' }).click()
      }
      await expect(menu.getByText(words.save, { exact: true })).toBeVisible()
      await menu.getByText(words.reset, { exact: true }).click()
      await settle(page)
      await expect(modified).toHaveCount(0)
      await expect(title).toHaveText(baseName)
      expect(
        new URLSearchParams(await page.evaluate(() => window.location.search)).has('severity')
      ).toBe(false)
      compare(`/findings ${width} ${locale}: reset to the view`, changed, await snap(page))
    })
  }

  test('/findings the chips row ends with Clear filters only', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings?severity=critical&source=pentest')
    const chips = page.locator('main [data-slot="filter-chips-row"]:visible').first()
    await expect(chips).toBeVisible({ timeout: 45_000 })
    await expect(chips.locator('[data-slot="filter-chips-clear"]')).toBeVisible()
    await expect(chips.getByRole('button', { name: /reset/i })).toHaveCount(0)
  })
}

/**
 * A list says its count once (owner rule): one `data-slot="list-count"`
 * beside the view name, and the same number with a noun ("26 findings")
 * nowhere else on the page, with and without a filter. Not counted: the
 * pager's range (navigation), tab counts (other queues), the rows and cards,
 * and text for assistive technology only.
 */
async function countPlaces(page: Page) {
  return page.evaluate(() => {
    const main = document.querySelector('main')!
    const shown = (el: Element) => el.getClientRects().length > 0 && !el.closest('.sr-only')
    const counts = Array.from(main.querySelectorAll('[data-slot="list-count"]')).filter(shown)
    // The number as shown (the sentence for screen readers is apart).
    const shownCount = counts[0]?.querySelector('[aria-hidden="true"]') ?? counts[0]
    const text = (shownCount?.textContent ?? '').replace(/\s+/g, ' ').trim()
    const number = text.match(/^[\d.,]+\+?/)?.[0]
    const others: string[] = []
    if (number) {
      // The count's own sentence ("26 findings"): said again anywhere else is
      // the count twice. A row's "1 run" is not the list's "1 scan
      // configuration", so the noun counts too.
      const sentence = (counts[0]?.querySelector('.sr-only')?.textContent ?? '')
        .replace(/\s+/g, ' ')
        .trim()
      const esc = (sentence || number).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const re = sentence
        ? new RegExp(`(^|\\s)${esc}(\\s|$|[.,;:])`, 'iu')
        : new RegExp(`(^|\\s)${esc}\\+?\\s+\\p{L}`, 'u')
      // An action's own label ("Add all 12 matching to group") names what it
      // acts on; it is not the list's count said again.
      const skip =
        '[data-slot="list-count"], [data-slot="data-table-pager"], [role="tablist"], [data-slot="table-container"], [data-slot="mobile-card"], [data-phone-card], nav, aside, .sr-only, [role="dialog"], button, a, [role="button"]'
      const walker = document.createTreeWalker(main, NodeFilter.SHOW_TEXT)
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        const el = n.parentElement
        if (!el || el.closest(skip) || !shown(el)) continue
        const line = (el.textContent ?? '').replace(/\s+/g, ' ').trim()
        if (re.test(line)) others.push(line.slice(0, 60))
      }
    }
    return { counts: counts.length, text, number, others: [...new Set(others)] }
  })
}

export function saysItsCountOnce(route: Route) {
  const list: ListSpec = LISTS[route]
  for (const width of [1440, 390]) {
    test(`${route} says its count once at ${width}px`, async ({ page }) => {
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
      const join = route.includes('?') ? '&' : '?'
      for (const qs of [
        '',
        `${join}${list.filters[0][0]}=${encodeURIComponent(list.filters[0][1])}`,
      ]) {
        const shown = await openList(
          page,
          `${route}${qs}`,
          list.optional ? 15_000 : 45_000,
          toolbarShown(list)
        )
        test.skip(!!list.optional && !shown, NO_LIST)
        await expect(page.locator('main [data-slot="list-count"]:visible')).toHaveText(/\d/, {
          timeout: 45_000,
        })
        await settle(page)
        const r = await countPlaces(page)
        test
          .info()
          .annotations.push({ type: `${route}${qs} ${width}`, description: JSON.stringify(r) })
        expect(r.counts, `${route}${qs} at ${width}: one list count`).toBe(1)
        expect(r.number, `${route}${qs} at ${width}: the count shows a number`).toMatch(/^\d/)
        expect(r.others, `${route}${qs} at ${width}: the count said again`).toEqual([])
      }
    })
  }
}

/**
 * The sidebar's quick views: on the hovered row the pin takes the count's
 * place; the count is never drawn under it (counts of 1 to 4 digits).
 */
export function quickViewPinNeverCoversTheCount() {
  test('a quick view row: the pin never covers its count', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.setViewportSize({ width: 1440, height: 900 })
    const counts = [7, 26, 345, 1234]
    await page.route('**/api/v1/findings/quick-views*', async (route) => {
      const response = await route.fetch()
      const json = await response.json()
      ;(json.views ?? []).forEach((v: { count?: number }, i: number) => {
        v.count = counts[i % counts.length]
      })
      await route.fulfill({ response, json })
    })
    await page.goto('/findings')
    const rows = page.locator(
      '[data-slot="sidebar"] [data-slot="sidebar-menu-sub-item"]:has([data-slot="pin-action"])'
    )
    await expect(rows.first()).toBeVisible({ timeout: 30_000 })
    const n = Math.min(await rows.count(), counts.length)
    expect(n).toBeGreaterThan(0)
    for (let i = 0; i < n; i++) {
      const row = rows.nth(i)
      await row.hover()
      await settle(page)
      const r = await row.evaluate((li) => {
        const pin = li.querySelector('[data-slot="pin-action"]')!.getBoundingClientRect()
        const count = li.querySelector('[data-slot="nav-count"]')
        if (!count) return { text: '', overlap: false, hidden: true }
        const c = count.getBoundingClientRect()
        const hidden = getComputedStyle(count).visibility === 'hidden'
        const overlap =
          c.right > pin.left && c.left < pin.right && c.bottom > pin.top && c.top < pin.bottom
        return { text: count.textContent ?? '', overlap, hidden }
      })
      expect(r.hidden || !r.overlap, `row ${i} (count ${r.text}): the pin covers the count`).toBe(
        true
      )
    }
  })
}

/**
 * One overflow menu per page, never one of a single item: wide, the view's
 * title row ends with its buttons and Copy link sits in the page header's
 * More; narrow, Export and Task fold into the title row's More with Copy
 * link, and the header's More does not repeat it.
 */
export function oneOverflowMenu() {
  for (const width of [1440, 1024]) {
    test(`one overflow menu holds Copy link at ${width}px`, async ({ page }) => {
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/findings')
      const row = page.getByTestId('findings-toolbar-primary')
      await expect(row).toBeVisible({ timeout: 30_000 })
      await settle(page)
      const rowMore = row.getByRole('button', { name: 'More actions' })
      const header = page.locator('main header, main [data-slot="page-header"]').first()
      const headerMore = header.getByRole('button', { name: 'More actions' })
      const items = async (trigger: typeof rowMore) => {
        await trigger.click()
        const menu = page.getByRole('menu')
        await expect(menu).toBeVisible()
        const names = await menu.getByRole('menuitem').allInnerTexts()
        await page.keyboard.press('Escape')
        await expect(menu).toBeHidden()
        return names.map((n) => n.trim())
      }
      const rowShown = await rowMore.isVisible()
      const rowItems = rowShown ? await items(rowMore) : []
      const headerItems = (await headerMore.isVisible()) ? await items(headerMore) : []
      test.info().annotations.push({
        type: `menus at ${width}`,
        description: JSON.stringify({ rowItems, headerItems }),
      })
      for (const list of [rowItems, headerItems])
        expect(list.length === 0 || list.length >= 2).toBe(true)
      const copyIn = [rowItems, headerItems].filter((l) => l.includes('Copy link')).length
      expect(copyIn, 'Copy link in exactly one menu').toBe(1)
      if (width === 1440) expect(rowShown, 'no title-row More when wide').toBe(false)
    })
  }
}

/**
 * Under Compliance the benchmarks block is the list's content: it draws under
 * the chips row and above the rows, so the title row and the toolbar hold
 * still when it arrives and when it folds. The seed has no compliance checks:
 * the endpoint answers late with one benchmark.
 */
export function benchmarksNeverMoveTheHeader() {
  for (const width of [1440, 390]) {
    test(`/findings Compliance benchmarks never move the header at ${width}px`, async ({
      page,
    }) => {
      await page.setViewportSize({ width, height: 900 })
      await page.emulateMedia({ reducedMotion: 'reduce' })
      let release: () => void = () => undefined
      const gate = new Promise<void>((r) => (release = r))
      await page.route(/\/api\/v1\/findings\/compliance\/benchmarks(\?|$)/, async (route) => {
        await gate
        await route.fulfill({
          json: {
            data: [
              {
                key: 'e2e-example-benchmark',
                name: 'Example benchmark',
                version: '1.0',
                framework: 'cis',
                assets: 4,
                failing_assets: 1,
                counts: {
                  pass: 9,
                  fail: 3,
                  manual: 0,
                  not_applicable: 0,
                  error: 0,
                  excepted: 0,
                  applicable: 12,
                },
                pass_rate: 0.75,
                last_checked_at: '2026-11-01T00:00:00Z',
              },
            ],
          },
        })
      })
      await page.goto('/findings?practice=compliance')
      await expect(
        page.locator('main [data-slot="list-toolbar"] [data-slot="list-search-input"]').first()
      ).toBeVisible({ timeout: 45_000 })
      await settle(page)
      const before = await firstPaint(page, toolbarShown(LISTS['/findings']))
      release()
      const panel = page.locator('main [data-testid="compliance-benchmarks-panel"]')
      await expect(panel).toBeVisible({ timeout: 20_000 })
      await settle(page)
      compareFirstPaint(
        'benchmarks arrive',
        before,
        await firstPaint(page, toolbarShown(LISTS['/findings']))
      )
      // Placement: under the toolbar (and its chips row), above the rows.
      const order = await page.evaluate(() => {
        const top = (sel: string) =>
          document.querySelector(`main ${sel}`)?.getBoundingClientRect() ?? null
        const bar = top('[data-slot="list-toolbar-region"]')
        const block = top('[data-slot="table-before-rows"]')
        return { barBottom: bar?.bottom ?? null, blockTop: block?.top ?? null }
      })
      expect(order.blockTop, JSON.stringify(order)).not.toBeNull()
      expect(order.blockTop!).toBeGreaterThanOrEqual(order.barBottom!)
      // Folding it moves nothing above it either.
      const folded = await firstPaint(page, toolbarShown(LISTS['/findings']))
      await page.locator('main [data-slot="compliance-benchmarks-fold"]').click()
      await expect(panel).toBeHidden()
      await settle(page)
      compareFirstPaint(
        'benchmarks fold',
        folded,
        await firstPaint(page, toolbarShown(LISTS['/findings']))
      )
      await page.evaluate(() =>
        window.localStorage.removeItem('findings.complianceBenchmarks.folded')
      )
    })
  }
}
