import { test, type Page } from '@playwright/test'
import { submitSignIn } from './auth'

/**
 * MVP acceptance v2 (agent-ops/ui-v2/MVP-ACCEPTANCE.md): the viewport matrix
 * and the detectors that the first acceptance pass missed at 390, 1024 and
 * 1440 px only (owner reports 2026-11-22):
 *   - the finding rail's watchers control ran past its column near 2000 px;
 *   - /my-work spent whole rows on "Updated ..." and "Top N of M" at iPad width;
 *   - /remediation/campaigns cut its Due column ("..., overd") with no ellipsis
 *     at 1024 px with the left sidebar expanded.
 *
 * Kinds (each a list of plain lines, empty when the page passes):
 *   pastPanel        a control whose box runs past its column, rail or frame
 *                    (not a node of a zoomable canvas: React Flow)
 *   cutText          text cut at a frame or table scroller edge, no ellipsis
 *   wastedRow        a toolbar row above the first data row that holds only
 *                    meta text or one small control and is mostly empty;
 *                    facts are content (a MetaLine of label and value, a <dl>,
 *                    a bordered fact card), a notice or a lone label is not
 *   duplicateAction  two primary buttons with one name or one target
 *   wideStretch      at 1900 px and up: a field or text line wider than 960 px,
 *                    or a side rail more than 400 px from its content (in a
 *                    grid wider than 960 px: a capped frame does not stretch)
 *   joined           a field and a button side by side less than 8 px apart
 *                    (the kit gap), not one segmented group: /scope's Filters
 *                    button against its search box. A field under a sticky or
 *                    fixed bar is on another layer than the bar's buttons
 *   emptyTail        the full-page picture is more than 1.5x as tall as the
 *                    bottom of its last visible content (and taller than the
 *                    window): a boxed list's height leaked into the page, or
 *                    the picture grew by a scroller nobody scrolls the page with
 *   cutMeaning       a text that ends in an ellipsis (text-overflow) or a line
 *                    clamp that hides lines, so part of what it says is lost:
 *                    "takes no new jo…", "mất kết nối, SDK, heart…" (owner
 *                    reports 2026-11-25). Exempt only (a) a cell of a name or
 *                    title column (`data-column-kind="name"`, the DataTable's
 *                    name kind and the phone card's title) and (b) an element
 *                    opted out with `data-cut-tooltip`, each only while its
 *                    full text is reachable: a `title`, `aria-label` or
 *                    `aria-description` holding it, or a tooltip trigger. A
 *                    line reads `cut "<visible>…" of "<full>" at <selector>`.
 *   hollowCard       a framed card (rounded, bordered, with a background) whose
 *                    last visible content ends more than max(64 px, 30% of the
 *                    card's height) above its inner bottom edge: a row floor
 *                    or a stored height left a blank band (the dashboard's
 *                    CTEM loop stood 120 px above its tiles, owner 2026-11-26).
 *                    Exempt: (a) a card in a row whose neighbour fills it
 *                    (equal-height rows are by design: the neighbour sets the
 *                    height), and (b) the fill areas of HOLLOW_FILL, whose
 *                    whole box is content: a chart's plot box, a zoomable
 *                    canvas, the shared empty state (it centres itself in the
 *                    room it is given). A line reads `card ends <gap>px below
 *                    its last content (<height>px tall) at <selector>`.
 *   deadSpace        a control with a trailing icon (combobox, menu or popup
 *                    button, a button ending in an svg) whose icon stands more
 *                    than 12 px from its inner end, or more than 16 px after
 *                    its text ("Target: All" sized for "Known exploited", its
 *                    chevron mid-way, owner 2026-11-27). The second is asked
 *                    of filter tokens, menu buttons and buttons only (a
 *                    select field may be given a width, its chevron pinned to
 *                    its end), and not of one holding one width by design
 *                    (`data-hold-width`, a ToolbarSlot) or filling its column
 *   floatingAction   a list row's (li, listitem, 480 px and wider) kit button
 *                    with nothing of the row after it, yet more than 64 px
 *                    from both the row's start and its end ("Validate" mid-way
 *                    along a 1500 px "Waiting for you" row)
 *   tallControl      a button, select or filter token more than 1.5x (and
 *                    12 px) taller than the median of the controls beside it
 *                    in its flex or grid row (a select wrapped onto 3 lines)
 *   pastEdge         a control past the window's edge, or past the page
 *                    column (#content), outside a box made to scroll sideways
 *                    (table scroller, tab strip, canvas, `data-scroll-x`, or a
 *                    box that does scroll sideways): toolbar buttons cut at
 *                    the window's right edge
 *   sizeMismatch     controls side by side in one row (a toolbar, a header, a
 *                    button group) that differ in height or centre line, or
 *                    whose buttons (or fields) differ in font size
 *                    (probeRowMix of helpers/page-anatomy.ts with `fonts`, on
 *                    the page, not over an overlay): "All severities" wrapped
 *                    taller than the search beside it
 *   cellCrowd        in a table row or a ruled list row, a text line or a
 *                    chip closer than 4 px to the row's ruled top or bottom
 *                    edge, or across it ("Ransomware" crossing the row's
 *                    bottom border)
 */

export type MatrixBreaks = {
  pastPanel: string[]
  cutText: string[]
  wastedRow: string[]
  duplicateAction: string[]
  wideStretch: string[]
  joined: string[]
  emptyTail: string[]
  cutMeaning: string[]
  hollowCard: string[]
  deadSpace: string[]
  floatingAction: string[]
  tallControl: string[]
  pastEdge: string[]
  sizeMismatch: string[]
  cellCrowd: string[]
}

export const MATRIX_KINDS: (keyof MatrixBreaks)[] = [
  'pastPanel',
  'cutText',
  'wastedRow',
  'duplicateAction',
  'wideStretch',
  'joined',
  'emptyTail',
  'cutMeaning',
  'hollowCard',
  'deadSpace',
  'floatingAction',
  'tallControl',
  'pastEdge',
  'sizeMismatch',
  'cellCrowd',
]

/** Widths of the v2 matrix with the height of their device class. */
export const MATRIX_V2: { width: number; height: number }[] = [
  { width: 360, height: 780 },
  { width: 390, height: 844 },
  { width: 430, height: 932 },
  { width: 768, height: 1180 },
  { width: 820, height: 1180 },
  { width: 1024, height: 820 },
  { width: 1180, height: 820 },
  { width: 1280, height: 900 },
  { width: 1440, height: 900 },
  { width: 1920, height: 1080 },
  // A 2560 x 1440 screen at 125 % (a 25 to 27 inch desktop).
  { width: 2048, height: 1152 },
  { width: 2560, height: 1440 },
]

/** The reduced set for CI shards (LAYOUT_MATRIX=ci). */
export const MATRIX_CI = [390, 1024, 1440, 1920]

/**
 * Widths where the stored sidebar preference (cookie `sidebar_state`) changes
 * the layout: from 1024 px the sidebar is expanded or collapsed by that
 * preference. Below 1024 px it is always the icon rail (hooks/use-mobile.ts),
 * so 768 and 820 px have one layout only and run once.
 */
export const SIDEBAR_WIDTHS = [1024, 1180, 1280]

/**
 * Signed-out pages: run in a fresh context, without the signed-in session.
 * /oauth/device is not one: it needs a session (the proxy sends a signed-out
 * visitor to /login), so the matrix opens it signed in, as spec 75c does.
 */
export const AUTH_ROUTES = [
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/verify-email',
]

const submit = (page: Page) => page.locator('main button[type="submit"]').first().click()
const shown = (page: Page, sel: string) =>
  page
    .locator(sel)
    .first()
    .waitFor({ timeout: 15_000 })
    .catch(() => {})

/**
 * E-mail states need a stack whose platform e-mail goes to a mail catcher
 * (Mailpit): E2E_MAIL_API is its HTTP API. The accounts are example.com ones
 * the stack seeds: mail-reset@example.com (verified) and
 * mail-verify-1..120@example.com (not verified).
 */
const MAIL_API = process.env.E2E_MAIL_API
const MAIL_VERIFY_POOL = 120

/*
 * Password and link requests share a per-address limit of three a minute. The
 * matrix stack (agent-ops box.sh) puts a small proxy in front of the web that
 * gives each request its own client address, and only that web trusts it
 * (TRUST_PROXY_HEADERS=true). The spec sends no forwarding headers itself.
 */

/** The newest message to an address in the mail catcher, as text. */
async function mailTo(page: Page, address: string): Promise<string | null> {
  for (let i = 0; i < 20; i++) {
    const found = await page.request
      .get(`${MAIL_API}/api/v1/search?query=${encodeURIComponent(`to:"${address}"`)}`)
      .then((r) => r.json())
      .catch(() => null)
    const id = found?.messages?.[0]?.ID
    if (id) {
      const msg = await page.request.get(`${MAIL_API}/api/v1/message/${id}`).then((r) => r.json())
      return `${msg.Text ?? ''}\n${msg.HTML ?? ''}`
    }
    await page.waitForTimeout(500)
  }
  return null
}

/**
 * Opens the link of a fresh verification e-mail: asks for one for an unused
 * account of the pool (a used account is verified and gets no e-mail) and
 * opens its /verify-email link on the web under test.
 */
let nextVerify = 0
async function openVerificationLink(page: Page) {
  if (!MAIL_API) throw new Error('E2E_MAIL_API is not set: this state needs a mail catcher')
  for (let tries = 0; tries < 6; tries++) {
    // Each worker takes its own slice of the pool, one address per try: two
    // workers never open the same link.
    const slice = Math.floor(MAIL_VERIFY_POOL / 4)
    const address = `mail-verify-${1 + (test.info().workerIndex % 4) * slice + (nextVerify++ % slice)}@example.com`
    // Sent by the page itself, as the sign-in page does: same origin, through the web.
    const sent = await page.evaluate(async (email) => {
      const r = await fetch('/api/v1/auth/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      })
      return `${r.status} ${(await r.text()).slice(0, 200)}`
    }, address)
    console.log(`[matrix] resend-verification ${address}: ${sent}`)
    const body = await mailTo(page, address)
    // The text part writes a link as "Label (URL)": the brackets end the URL.
    const link = body?.match(/https?:\/\/[^\s"'<>()]*\/verify-email[^\s"'<>()]*/)?.[0]
    if (!link) continue
    const u = new URL(link.replace(/&amp;/g, '&'))
    await page.goto('about:blank')
    await page.goto(u.pathname + u.search + u.hash)
    return
  }
  throw new Error('no verification e-mail arrived')
}

/**
 * Entry-page states the matrix opens beside the bare route, so a link page is
 * checked in its real states and not only as "invalid link" (MVP v2 batch 9).
 * The key is a LAYOUT_ROUTES entry (`/reset-password@form`); `path` is the
 * page opened and `act` what a person does on it before the checks. The acts
 * only fill a form with values the server refuses: nothing is bypassed.
 * `as` names another seeded account (web/e2e/ci/seed.sh) the page is opened
 * by, in a context of its own: the page then shows that account's state
 * (an organization picker, an invitation to accept). A path or account that
 * needs a seed value the stack did not print is left out: the route skips.
 */
type RouteState = {
  path: string
  act?: (page: Page) => Promise<void>
  as?: () => { email: string; password: string } | null
  /**
   * The overlay `act` opens (a dialog or sheet selector): the checks run in
   * it and the picture is the window, as for the matrix overlays. When the
   * act opened none (a page without that editor), the variant reads
   * "no such overlay" instead of measuring the page under it.
   */
  layer?: string
}

/** The editor dialog a settings row opens: its button carries `data-editor`. */
const EDITOR_LAYER = '[role=dialog]'

function editorStates(route: string, editors: string[]): Record<string, RouteState> {
  return Object.fromEntries(
    editors.map((editor) => [
      `${route}@${editor}`,
      {
        path: route,
        layer: EDITOR_LAYER,
        act: async (page: Page) => {
          await page.locator(`main [data-editor="${editor}"]`).first().click({ timeout: 15_000 })
          await page.locator(`${EDITOR_LAYER}:visible`).first().waitFor({ timeout: 10_000 })
          // Past its open animation.
          await page.waitForTimeout(400)
        },
      },
    ])
  )
}

const account = (prefix: string) => () => {
  const email = process.env[`${prefix}_EMAIL`]
  const password = process.env[`${prefix}_PASSWORD`]
  return email && password ? { email, password } : null
}

/**
 * Signs `page` in as another account through the form and stays wherever the
 * sign-in lands (an account of two organizations stops at the picker).
 */
export async function signInAs(page: Page, who: { email: string; password: string }) {
  // A loaded build box can take the sign-in past submitSignIn's 30 s: the
  // form is filled and sent once more before the test gives up.
  for (let attempt = 1; ; attempt++) {
    await page.goto('/login', { timeout: 60_000 })
    await page.waitForLoadState('networkidle').catch(() => {})
    if (!new URL(page.url()).pathname.startsWith('/login')) return
    await page.locator('main input[name="email"]').fill(who.email)
    await page.locator('main input[name="password"]').fill(who.password)
    try {
      await submitSignIn(page, (url) => !url.pathname.startsWith('/login'))
      return
    } catch (e) {
      if (attempt >= 2) throw e
    }
  }
}

export const ROUTE_STATES: Record<string, RouteState> = {
  // An account of two organizations after its password: the organization
  // picker, and "new organization" from it (both need the picker's cookie
  // and no organization chosen yet).
  '/select-tenant': { path: '/select-tenant', as: account('E2E_SWITCH') },
  '/onboarding/create-team': { path: '/onboarding/create-team', as: account('E2E_SWITCH') },
  // An invitation link, opened by the invited account (it has an
  // organization of its own): the invitation to accept. The old path form
  // /invitations/<token> only redirects to this fragment form.
  '/invitations/[token]': {
    get path() {
      const token = process.env.E2E_INVITEE_TOKEN
      return token ? `/invitations#token=${encodeURIComponent(token)}` : '/invitations/[token]'
    },
    as: account('E2E_INVITEE'),
  },
  // A pending write an AI application asked for: Approve and Deny. Opened
  // when the stack's seed made one for the owner and printed its id.
  '/mcp/confirm/[id]': {
    get path() {
      const id = process.env.E2E_MCP_CONFIRM_ID
      return id ? `/mcp/confirm/${encodeURIComponent(id)}` : '/mcp/confirm/[id]'
    },
  },
  // The dashboard's editor (Customize): its previews stand as the widgets
  // will on the dashboard, so the hollowCard check covers it too.
  '/@customize': {
    path: '/?customize=1',
    act: async (page) => {
      await page
        .locator('main [data-testid="editor-grid"]')
        .waitFor({ state: 'visible', timeout: 20_000 })
      await page.waitForLoadState('networkidle').catch(() => {})
    },
  },
  // Wrong credentials of an account that does not exist: the error banner.
  '/login@error': {
    path: '/login',
    act: async (page) => {
      await page.locator('main input[name="email"]').fill('nobody@example.com')
      await page.locator('main input[name="password"]').fill('Not-the-password-1')
      await submit(page)
      await shown(page, 'main [role="alert"]')
    },
  },
  // An invitation link opens the sign-up form even when open sign-up is off.
  '/register@invite': { path: '/register?returnTo=/invitations/example' },
  // After the request for a seeded account: the "check your email" state
  // (on a stack with a mail catcher, see MAIL_API).
  '/forgot-password@sent': {
    path: '/forgot-password',
    act: async (page) => {
      await page.locator('main input[name="email"]').fill('mail-reset@example.com')
      await submit(page)
      await page
        .locator('main input[name="email"]')
        .waitFor({ state: 'detached', timeout: 15_000 })
        .catch(() => {})
    },
  },
  // A link with a token: the new-password form.
  '/reset-password@form': { path: '/reset-password#token=synthetic-reset-token' },
  // The same form sent with a token the server does not know: expired link.
  '/reset-password@expired': {
    path: '/reset-password#token=synthetic-reset-token',
    act: async (page) => {
      await page.locator('main input[name="password"]').fill('Correct-Horse-Battery-9')
      await page.locator('main input[name="confirmPassword"]').fill('Correct-Horse-Battery-9')
      await submit(page)
      await shown(page, 'main [role="alert"]')
    },
  },
  // The link of a real verification e-mail: the "verified" state.
  '/verify-email@verified': {
    path: '/verify-email',
    act: async (page) => {
      await openVerificationLink(page)
      await page
        .locator('main [role="status"], main [role="alert"]')
        .first()
        .waitFor({ timeout: 15_000 })
        .catch(() => {})
    },
  },
  // A code the server does not know: the invalid-code banner.
  '/oauth/device@invalid': {
    path: '/oauth/device',
    act: async (page) => {
      await page.locator('#device-user-code').fill('BCDF-GHJK')
      await submit(page)
      await shown(page, 'main [role="alert"]')
    },
  },
  // A page tab the bare route does not open: /sensors starts on its sensors
  // list, the scan zones (their list and the coverage card) are a tab.
  '/sensors@zones': { path: '/sensors?tab=zones' },
  // A pentest campaign's Checklist tab (the seed records passed, failed, N/A
  // and untested results on its OWASP Top 10 checklist).
  '/pentest/campaigns/[id]@checklist': { path: '/pentest/campaigns/[id]?view=checklist' },
  // A list in Query mode: the search field is the query editor, one line
  // (`@query`) and expanded (`@query-open`), the state most of a filter
  // edit is written in.
  ...queryStates('/findings'),
  ...queryStates('/assets'),
  ...queryStates('/scans'),
  // Settings > Approvals: each approval type's editor, opened from its row,
  // and the page with lowered protections waiting (its data in ROUTE_DATA of
  // helpers/layout-breaks.ts).
  ...editorStates('/settings/approvals', [
    'false-positives',
    'accepted-risks',
    'suppression-rules',
    'approvers',
    'deadlines',
    'backup-contact',
  ]),
  '/settings/approvals@waiting': { path: '/settings/approvals' },
  // A text of its own applied on top of the view (the view then reads as
  // changed: Modified and the Save view menu join the title row), then the
  // editor expanded: the state a filter edit is left in.
  '/findings@query-applied': {
    path: '/findings?mode=query',
    act: async (page) => {
      const field = page.locator('main [data-slot="list-search-query"] [role="combobox"]')
      await field.first().waitFor({ state: 'visible', timeout: 20_000 })
      await page.waitForFunction(
        () =>
          !document.querySelector<HTMLInputElement>(
            'main [data-slot="list-search-query"] [role="combobox"]'
          )?.disabled,
        undefined,
        { timeout: 20_000 }
      )
      const before = page.url()
      await field.first().fill('practice!=compliance state=open severity>=medium')
      // The run button (Enter would take an open suggestion first).
      await page.locator('main [data-slot="query-apply"]').first().click()
      await page.waitForURL((u) => u.toString() !== before, { timeout: 15_000 })
      await expandQueryEditor(page)
    },
  },
}

/**
 * Opens the query editor's expanded form: the expand button in the field
 * from 768 px, or the field's "More" menu on a phone (help, then expand). The
 * focus leaves the editor after, so the checks see the page and not the
 * suggestion list.
 */
async function expandQueryEditor(page: Page) {
  const controls = page.locator('main [data-slot="query-field-controls"]').first()
  await controls.waitFor({ state: 'visible', timeout: 15_000 })
  const expand = controls.locator('button[aria-pressed]')
  if (await expand.isVisible()) await expand.click()
  else {
    // The More menu's trigger: the only popup button drawn on a phone (help
    // and expand are inside that menu there).
    await controls.locator('button[aria-haspopup]:visible').first().click()
    await page
      .locator('[data-slot="action-sheet-row"], [role="menuitem"]')
      .nth(1)
      .click({ timeout: 5_000 })
  }
  await page
    .locator('main [data-slot="query-editor-expanded"] textarea')
    .waitFor({ state: 'visible', timeout: 5_000 })
  // Past its open animation.
  await page.waitForTimeout(400)
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur())
}

function queryStates(route: string): Record<string, RouteState> {
  const path = `${route}?mode=query`
  return {
    [`${route}@query`]: { path },
    [`${route}@query-open`]: { path, act: expandQueryEditor },
  }
}

/** The page a matrix route opens: its state's path, or the route itself. */
export const statePath = (route: string) => ROUTE_STATES[route]?.path ?? route

/**
 * The path a page must be on after opening `url`, the address resolveRoute
 * produced (`/assets/01a2…`, not the `/assets/[id]` template): no query, no
 * fragment, encoded the way the browser reports `location.pathname`.
 */
export function openedPath(url: string): string {
  return new URL(url, 'http://opened.invalid').pathname
}

/** Whether a matrix route (or state) is a signed-out page. */
export const isSignedOutRoute = (route: string) =>
  AUTH_ROUTES.includes(statePath(route).split(/[?#]/)[0])

/** Widths that also get the empty and one-row data and the main overlays. */
export const OVERLAY_WIDTHS = [390, 1440]

/**
 * Widths that also open a list row's quick-view sheet (overlay `detail`)
 * with the sidebar expanded: a tablet in landscape, where the sheet covers
 * most of a narrow list (owner report 2026-11-24, the emerging-threat sheet).
 */
export const DETAIL_OVERLAY_WIDTHS = [1024]

export function matrixWidths(mode: string | undefined): { width: number; height: number }[] {
  if (mode === 'ci') return MATRIX_V2.filter((w) => MATRIX_CI.includes(w.width))
  const only = process.env.LAYOUT_WIDTHS?.split(',').map(Number).filter(Boolean)
  return only?.length ? MATRIX_V2.filter((w) => only.includes(w.width)) : MATRIX_V2
}

/**
 * List endpoints that give the first id of a detail route (`/findings/[id]`).
 * `own` takes the first row that is not a built-in one (`is_system` or
 * `is_system_template` true): a built-in scan workflow or pentest template
 * opens read-only, the organization's own copy is the page people edit.
 * The platform console's (web/console) lists are under /api/v1/admin.
 */
const DETAIL_LISTS: { prefix: string; list: string; key?: string; own?: boolean }[] = [
  { prefix: '/assets/groups/', list: '/api/v1/asset-groups?per_page=1' },
  { prefix: '/assets/', list: '/api/v1/assets?per_page=1' },
  { prefix: '/components/', list: '/api/v1/components?per_page=1' },
  { prefix: '/cycles/', list: '/api/v1/ctem-cycles?per_page=1' },
  { prefix: '/emerging-threats/', list: '/api/v1/emerging-threats?per_page=1' },
  { prefix: '/findings/', list: '/api/v1/findings?per_page=1' },
  { prefix: '/programs/', list: '/api/v1/programs?per_page=1' },
  { prefix: '/scans/workflows/', list: '/api/v1/scan-workflows?per_page=100', own: true },
  { prefix: '/scans/', list: '/api/v1/scans?per_page=1' },
  { prefix: '/remediation/campaigns/', list: '/api/v1/remediation/campaigns?per_page=1' },
  { prefix: '/remediation/tasks/', list: '/api/v1/remediation/tasks?per_page=1' },
  { prefix: '/pentest/campaigns/', list: '/api/v1/pentest/campaigns?per_page=1' },
  { prefix: '/pentest/findings/', list: '/api/v1/pentest/findings?per_page=1' },
  {
    prefix: '/settings/integrations/import-mappings/',
    list: '/api/v1/import-mappings?per_page=1',
  },
  {
    prefix: '/settings/integrations/ticketing/mappings/',
    list: '/api/v1/integrations/ticket-mappings?per_page=1',
  },
  {
    prefix: '/settings/pentest/templates/',
    list: '/api/v1/pentest/templates?per_page=100',
    own: true,
  },
  {
    prefix: '/vulnerabilities/',
    list: '/api/v1/vulnerability-exposures?per_page=1',
    key: 'cve_id',
  },
  // Platform console.
  { prefix: '/users/', list: '/api/v1/admin/platform-users?per_page=1' },
  { prefix: '/organizations/', list: '/api/v1/admin/tenants?per_page=1' },
]

const PLACEHOLDER = /\[[a-z]+\]|\{[a-z]+\}/i

/** Replaces `[id]` (or `{id}`, `[cve]`) with the first row's id; null when there is none. */
export async function resolveRoute(page: Page, route: string): Promise<string | null> {
  if (!PLACEHOLDER.test(route)) return route
  const at = route.search(PLACEHOLDER)
  const head = route.slice(0, at)
  const src = DETAIL_LISTS.find((d) => head === d.prefix)
  if (!src) return null
  await page.goto('/', { timeout: 60_000 }).catch(() => {})
  const id = await page.evaluate(
    async ({ url, field, own }) => {
      const res = await fetch(url, { credentials: 'same-origin' })
      if (!res.ok) return null
      const body = await res.json()
      const rows = body.data ?? body.items ?? body
      if (!Array.isArray(rows)) return null
      const row = own ? rows.find((r) => r && !r.is_system && !r.is_system_template) : rows[0]
      return row?.[field] ? String(row[field]) : null
    },
    { url: src.list, field: src.key ?? 'id', own: !!src.own }
  )
  return id ? route.replace(PLACEHOLDER, encodeURIComponent(id)) : null
}

/** Folder name for a route: `/findings/[id]` -> `findings-id`, `/` -> `home`. */
export const routeSlug = (route: string) =>
  route.replace(/\W+/g, '-').replace(/^-|-$/g, '') || 'home'

/**
 * `emptyTail`, measured on the window as the full-page picture takes it: the
 * document height against the bottom of the last visible content (text,
 * media, controls, painted boxes, cut to any box that clips them). A page
 * shorter than `windowHeight` never fails.
 */
export async function findEmptyTail(page: Page, windowHeight: number): Promise<string[]> {
  return page.evaluate((windowHeight) => {
    const docHeight = document.documentElement.scrollHeight
    let bottom = 0
    const walk = (el: Element, clip: number) => {
      const s = getComputedStyle(el)
      if (s.display === 'none' || s.visibility === 'hidden') return
      const r = el.getBoundingClientRect()
      const end = r.bottom + window.scrollY
      // A box as tall as the page (the shell, a page wrapper) paints its
      // background behind everything: it is not content.
      const filler = r.height >= docHeight * 0.9
      const paints =
        /^(IMG|svg|CANVAS|VIDEO|INPUT|TEXTAREA|SELECT|BUTTON)$/.test(el.tagName) ||
        Array.from(el.childNodes).some((n) => n.nodeType === 3 && n.textContent!.trim()) ||
        (!filler &&
          (!/rgba\(0, 0, 0, 0\)|transparent/.test(s.backgroundColor) ||
            parseFloat(s.borderBottomWidth) > 0))
      if (paints && r.width >= 2 && r.height >= 2) bottom = Math.max(bottom, Math.min(end, clip))
      const inner = s.overflowY === 'visible' ? clip : Math.min(clip, end)
      for (const c of el.children) walk(c, inner)
    }
    // The page's own content: the shell's sidebar runs the window's height.
    const root = document.querySelector('#content') ?? document.body
    for (const c of root.children) walk(c, Infinity)
    if (docHeight <= Math.max(windowHeight, bottom * 1.5)) return []
    return [
      `the page is ${docHeight}px tall, its last visible content ends at ${Math.round(bottom)}px`,
    ]
  }, windowHeight)
}

/** Runs the v2 detectors on the page (scope: `main` or an overlay selector). */
export async function findMatrixBreaks(
  page: Page,
  { scope = 'main' }: { scope?: string } = {}
): Promise<MatrixBreaks> {
  return page.evaluate((scope) => {
    const out = {
      pastPanel: [] as string[],
      cutText: [] as string[],
      wastedRow: [] as string[],
      duplicateAction: [] as string[],
      wideStretch: [] as string[],
      joined: [] as string[],
      emptyTail: [] as string[],
      cutMeaning: [] as string[],
      hollowCard: [] as string[],
      deadSpace: [] as string[],
      floatingAction: [] as string[],
      tallControl: [] as string[],
      pastEdge: [] as string[],
      // Filled by the matrix run (probeRowMix with fonts, helpers/page-anatomy.ts).
      sizeMismatch: [] as string[],
      cellCrowd: [] as string[],
    }
    const roots = Array.from(document.querySelectorAll(scope))
    if (!roots.length) return out
    const vw = document.documentElement.clientWidth
    const short = (s: string | null | undefined, n = 40) =>
      (s ?? '').replace(/\s+/g, ' ').trim().slice(0, n)
    const hidden = (el: Element): boolean => {
      for (let a: Element | null = el; a; a = a.parentElement) {
        const cs = getComputedStyle(a)
        if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return true
        if (a.getAttribute('aria-hidden') === 'true') return true
        const r = a.getBoundingClientRect()
        // Visually hidden (sr-only): a 1 px box that clips its content.
        if ((r.width <= 1 || r.height <= 1) && /hidden|clip/.test(cs.overflowX + cs.overflowY))
          return true
        if (cs.clip !== 'auto' && cs.clip !== '') return true
      }
      return false
    }
    const shown = (el: Element) => {
      const r = el.getBoundingClientRect()
      return r.width >= 1 && r.height >= 1 && !hidden(el)
    }
    const nameOf = (el: Element) =>
      short(
        el.getAttribute('aria-label') ||
          el.textContent ||
          el.getAttribute('title') ||
          el.getAttribute('placeholder'),
        30
      )
    const CONTROL =
      'button,a[href],[role=button],[role=tab],[role=combobox],[role=link],[role=switch],[role=checkbox],input:not([type=hidden]),select,textarea'
    const tracks = (el: Element) => {
      const cs = getComputedStyle(el)
      if (!/grid/.test(cs.display)) return 0
      return cs.gridTemplateColumns.split(' ').filter((t) => /px$/.test(t)).length
    }
    const isScroller = (el: Element) =>
      /auto|scroll|hidden|clip/.test(getComputedStyle(el).overflowX)
    const isRail = (el: Element) =>
      el.tagName === 'ASIDE' || /rail|sidebar/.test(el.getAttribute('data-slot') ?? '')

    // ---- pastPanel: a control past the column, rail or frame that holds it.
    // The container is the nearest grid column (a child of a grid with two
    // tracks or more), aside/rail, or overflow frame. A negative start margin
    // (a ghost button aligned to its text) may sit up to 12 px past the start.
    for (const root of roots) {
      for (const c of Array.from(root.querySelectorAll(CONTROL))) {
        const outer = c.parentElement?.closest(CONTROL)
        if (outer && root.contains(outer)) continue
        // A zoomable canvas (React Flow) draws its nodes at the zoom a person
        // picks, past its pane by design: not page layout.
        if (c.closest('.react-flow, [data-layout-canvas]')) continue
        if (!shown(c)) continue
        const r = c.getBoundingClientRect()
        let box: Element | null = null
        let what = ''
        for (let a = c.parentElement; a && a !== document.body; a = a.parentElement) {
          // A display:contents box has no box of its own (0 x 0): not a frame.
          if (getComputedStyle(a).display === 'contents') continue
          if (isScroller(a)) {
            box = a
            what = 'frame'
            break
          }
          if (isRail(a)) {
            box = a
            what = 'rail'
            break
          }
          if (a.parentElement && tracks(a.parentElement) >= 2) {
            box = a
            what = 'column'
            break
          }
        }
        if (!box) continue
        const b = box.getBoundingClientRect()
        // A control wholly past a scroller's edge (a table column out of view)
        // is reachable by scrolling; a cut one is the clipped check's (and
        // cutText's) business. Here: a control drawn past its box.
        if (what === 'frame' && /auto|scroll/.test(getComputedStyle(box).overflowX)) continue
        const end = Math.round(r.right - b.right)
        const start = Math.round(b.left - r.left)
        if (end > 2 || start > 12) {
          out.pastPanel.push(
            `control past its ${what} by ${Math.max(end, start)}px: "${nameOf(c)}" (${Math.round(r.width)}px in ${Math.round(b.width)}px)`
          )
        }
      }
    }

    // ---- cutText: a text cut by the frame around it (overflow clip, hidden,
    // or a table scroller) as the page opens, with no ellipsis to say so:
    // "Apr 29, 2026, overd" at the edge of a table at 1024 px.
    const ellipsisOn = (from: Element, to: Element) => {
      for (let a: Element | null = from; a; a = a.parentElement) {
        const cs = getComputedStyle(a)
        if (
          (cs.textOverflow === 'ellipsis' && !/flex|grid/.test(cs.display)) ||
          (/\d/.test(cs.webkitLineClamp) && /-webkit-(inline-)?box/.test(cs.display))
        )
          return true
        if (a === to) break
      }
      return false
    }
    const frameOf = (el: Element) => {
      for (let a = el.parentElement; a && a !== document.documentElement; a = a.parentElement) {
        if (isScroller(a) && a.getBoundingClientRect().width > 0) return a
      }
      return null
    }
    const seenText = new Set<string>()
    for (const root of roots) {
      const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
      for (let n = w.nextNode(); n; n = w.nextNode()) {
        const host = n.parentElement
        if (!host || !(n.textContent ?? '').trim() || hidden(host)) continue
        const frame = host === root ? null : isScroller(host) ? host : frameOf(host)
        if (!frame) continue
        const f = frame.getBoundingClientRect()
        const rg = document.createRange()
        rg.selectNodeContents(n)
        const boxes = Array.from(rg.getClientRects()).filter((b) => b.width > 1)
        const cutRight = boxes.some((b) => b.right > f.right + 1 && b.left < f.right - 1)
        const cutLeft = boxes.some((b) => b.left < f.left - 1 && b.right > f.left + 1)
        if ((!cutRight && !cutLeft) || ellipsisOn(host, frame)) continue
        // The shared page tab strip is one swipe row (owner 2026-11-21): a
        // label past its edge is by design when the strip really scrolls and
        // fades that edge. Like the sideways-scroller exemption in
        // text-breaks.ts, a strip that does not scroll, or a cut edge with no
        // fade, is still reported.
        const strip = frame.closest<HTMLElement>('[data-tab-strip]')
        if (
          strip &&
          /auto|scroll/.test(getComputedStyle(strip).overflowX) &&
          strip.scrollWidth > strip.clientWidth + 1
        ) {
          const rtl = getComputedStyle(strip).direction === 'rtl'
          const ds = strip.dataset
          const fadeRight = (rtl ? ds.fadeStart : ds.fadeEnd) === 'true'
          const fadeLeft = (rtl ? ds.fadeEnd : ds.fadeStart) === 'true'
          if ((!cutRight || fadeRight) && (!cutLeft || fadeLeft)) continue
        }
        const line = `text cut at a frame edge, no ellipsis: "${short(n.textContent)}"`
        if (!seenText.has(line)) out.cutText.push(line)
        seenText.add(line)
      }
    }

    // ---- wastedRow: rows between the page's tabs (or header) and the first
    // data row (or, with no rows, the first content block: the empty state).
    // With more than one such row, a row is wasted when it holds no field and
    // at most one small control beside its text: "Updated ...", "Top 5 of 40",
    // a caption with a lone Refresh button.
    for (const root of roots) {
      const rr = root.getBoundingClientRect()
      const anchorsAll = Array.from(
        // An overlay's title block (title and its one-line description) is
        // its header, not a wasted row.
        root.querySelectorAll(
          '[role=tablist], [data-slot="page-header"], [data-slot="entry-header"], h1, [data-slot="dialog-header"], [data-slot="sheet-header"], [data-slot="drawer-header"], [data-slot="detail-header"]'
        )
      ).filter(shown)
      let first: Element | undefined = Array.from(
        root.querySelectorAll(
          'tbody tr, [data-phone-card], [role=row]:not(:has([role=columnheader]))'
        )
      ).find(shown)
      // A grouped list drawn as phone cards: its group headers sit between
      // the cards, inside the cards' frame, so the list is that frame (the
      // parent of the groups), not the rows of the first group.
      let list: Element | null = first
        ? (first.closest('table, [role=table], [role=grid], ul, ol') ??
          first.closest('[role=group]:has(> [data-slot="row-group-header"])')?.parentElement ??
          first.parentElement)
        : null
      // An overlay without a list is a form: its labels and notes are not
      // rows of a list's toolbar.
      if (
        !first &&
        root.closest('[role=dialog], [data-slot="sheet-content"], [data-slot="drawer-content"]')
      )
        continue
      if (!first) {
        const below = anchorsAll.length
          ? Math.max(...anchorsAll.map((a) => a.getBoundingClientRect().bottom))
          : rr.top
        first = Array.from(root.querySelectorAll('*'))
          .filter((el) => {
            if (!shown(el)) return false
            const r = el.getBoundingClientRect()
            return r.top > below + 4 && r.height >= 120 && r.width >= rr.width * 0.6
          })
          .sort((x, y) => x.getBoundingClientRect().top - y.getBoundingClientRect().top)[0]
        list = first ?? null
      }
      if (!first || !list) continue
      const firstEl: Element = first
      const listEl: Element = list
      const fr = first.getBoundingClientRect()
      const lr = list.getBoundingClientRect()
      const anchors = anchorsAll.filter((a) => a.getBoundingClientRect().bottom <= fr.top)
      let top = anchors.length
        ? Math.max(...anchors.map((a) => a.getBoundingClientRect().bottom))
        : rr.top
      // In an overlay (a detail sheet of stacked sections), only the list's
      // own section counts: text under another section heading (Stages,
      // Timeline) above the list's heading belongs to that section, not to
      // the list's toolbar.
      if (
        root.closest('[role=dialog], [data-slot="sheet-content"], [data-slot="drawer-content"]')
      ) {
        const own = Array.from(root.querySelectorAll('h2, h3, h4, h5, h6, [role=heading]'))
          .filter(
            (h) =>
              shown(h) &&
              !h.closest(
                '[data-slot="dialog-header"], [data-slot="sheet-header"], [data-slot="drawer-header"], [data-slot="detail-header"]'
              ) &&
              h.getBoundingClientRect().bottom <= fr.top + 1
          )
          .map((h) => h.getBoundingClientRect().top)
        if (own.length) top = Math.max(top, Math.max(...own) - 1)
      }
      // Facts are content, not toolbar rows: a label and its value in a
      // MetaLine (two items or more, or one MetaItem "Label value"), a <dl>
      // fact grid, and a bordered fact card (the entry page's organization
      // card, a detail page's summary card). A card that holds the list or the
      // page's header is the page's frame, a card with fields is a form, and a
      // notice (alert, status, entry banner) is a notice row: none of them
      // makes its lines facts.
      const factCache = new Map<Element, boolean>()
      const isFactCard = (box: Element): boolean => {
        if (factCache.has(box)) return factCache.get(box)!
        const cs = getComputedStyle(box)
        const bordered =
          box.getAttribute('data-slot') === 'card' ||
          (['Top', 'Right', 'Bottom', 'Left'] as const).every(
            (side) => parseFloat(cs[`border${side}Width`]) > 0
          )
        let fact = false
        if (bordered && !box.contains(listEl) && !box.contains(firstEl)) {
          const b = box.getBoundingClientRect()
          const notice = box.matches(
            '[role=alert], [role=status], [role=note], [data-slot="alert"], [data-slot="entry-banner"], [data-slot*="callout"]'
          )
          const framesHeader = anchorsAll.some((a) => box.contains(a))
          // A panel with fields (a settings or notification form) is a tool,
          // not a card of facts.
          const form = !!box.querySelector(
            'input:not([type=hidden]), select, textarea, [role=combobox], [role=switch]'
          )
          // Two lines of text or more: a bordered chip or badge is not a card.
          const lines = new Set<number>()
          const tw = document.createTreeWalker(box, NodeFilter.SHOW_TEXT)
          for (let n = tw.nextNode(); n && lines.size < 2; n = tw.nextNode()) {
            if (!(n.textContent ?? '').trim() || !n.parentElement || hidden(n.parentElement))
              continue
            const rg = document.createRange()
            rg.selectNodeContents(n)
            const nr = rg.getBoundingClientRect()
            if (nr.height >= 1) lines.add(Math.round(nr.top / 4))
          }
          fact =
            !notice && !framesHeader && !form && b.width >= 120 && b.height >= 40 && lines.size >= 2
        }
        factCache.set(box, fact)
        return fact
      }
      const isFact = (el: Element): boolean => {
        const dl = el.closest('dl')
        if (dl && root.contains(dl) && dl.querySelector('dt') && dl.querySelector('dd')) return true
        const meta = el.closest('[data-slot="meta-line"]')
        if (meta && root.contains(meta)) {
          const parts = Array.from(meta.querySelectorAll('[data-slot="meta-line-item"]')).filter(
            shown
          )
          // MetaItem: the label as text, the value in the line's ink beside it.
          const keyValue = (p: Element) =>
            Array.from(p.childNodes).some(
              (k) => k.nodeType === 3 && (k.textContent ?? '').trim()
            ) && Array.from(p.children).some((k) => k.classList.contains('text-foreground'))
          if (parts.length >= 2 || parts.some(keyValue)) return true
        }
        for (let a: Element | null = el; a && a !== root && root.contains(a); a = a.parentElement)
          if (isFactCard(a)) return true
        return false
      }
      type Item = {
        r: DOMRect
        control: boolean
        field: boolean
        heading: boolean
        fact: boolean
        text: string
      }
      const items: Item[] = []
      for (const el of Array.from(root.querySelectorAll('*'))) {
        if (
          list.contains(el) ||
          el.closest(
            '[role=tablist], [data-slot="page-header"], [data-slot="entry-header"], [data-slot="dialog-header"], [data-slot="sheet-header"], [data-slot="drawer-header"], [data-slot="detail-header"]'
          )
        )
          continue
        const control = el.matches(CONTROL)
        const ownText = Array.from(el.childNodes).some(
          (k) => k.nodeType === 3 && (k.textContent ?? '').trim()
        )
        if (!control && !ownText) continue
        if (el.parentElement?.closest(CONTROL)) continue
        if (!shown(el)) continue
        // A text's own extent, not its block box: a paragraph is as wide as
        // its column, its words are not.
        let r = el.getBoundingClientRect()
        if (!control) {
          const rg = document.createRange()
          rg.selectNodeContents(el)
          r = rg.getBoundingClientRect()
        }
        if (r.top < top - 1 || r.bottom > fr.top + 1) continue
        if (r.right < lr.left || r.left > lr.right) continue
        items.push({
          r,
          control,
          field: el.matches('input, textarea, select, [role=combobox]'),
          heading: !!el.closest('h1, h2, h3, h4, h5, h6, [role=heading]'),
          fact: isFact(el),
          text: short(el.getAttribute('aria-label') || el.textContent, 60),
        })
      }
      items.sort((a, b) => a.r.top - b.r.top)
      const rows: Item[][] = []
      for (const it of items) {
        const mid = (it.r.top + it.r.bottom) / 2
        const row = rows.find((g) => g.some((o) => mid > o.r.top && mid < o.r.bottom))
        if (row) row.push(it)
        else rows.push([it])
      }
      if (rows.length < 2) continue
      for (const row of rows) {
        // A field, a heading, a fact or a paragraph (more than two lines) is content.
        if (row.some((o) => o.field || o.heading || o.fact || (!o.control && o.r.height > 44)))
          continue
        const controls = row.filter((o) => o.control)
        if (controls.length > 1) continue
        if (controls.length === 1 && controls[0].r.width >= lr.width * 0.4) continue
        out.wastedRow.push(
          `row of its own above the first ${list === first ? 'content' : 'data row'}: "${short(
            [...row]
              .sort((x, y) => x.r.left - y.r.left)
              .map((o) => o.text)
              .join(' | '),
            70
          )}"`
        )
      }
    }

    // ---- duplicateAction: primary buttons (kit default variant) with the
    // same name or the same link target.
    for (const root of roots) {
      const prim = Array.from(
        root.querySelectorAll('[data-slot="button"][data-variant="default"]')
      ).filter(shown)
      const byName = new Map<string, number>()
      const byHref = new Map<string, string[]>()
      for (const p of prim) {
        const n = nameOf(p).toLowerCase()
        if (n) byName.set(n, (byName.get(n) ?? 0) + 1)
        const h = p.getAttribute('href') ?? p.closest('a[href]')?.getAttribute('href')
        if (h && h !== '#') byHref.set(h, [...(byHref.get(h) ?? []), nameOf(p)])
      }
      for (const [n, k] of byName)
        if (k > 1) out.duplicateAction.push(`${k} primary buttons "${n}"`)
      for (const [h, names] of byHref) {
        if (names.length > 1 && new Set(names.map((x) => x.toLowerCase())).size > 1)
          out.duplicateAction.push(
            `${names.length} primary buttons to ${h}: "${names.join('", "')}"`
          )
      }
    }

    // ---- wideStretch: wide screens only.
    if (vw >= 1900) {
      for (const root of roots) {
        const fields = root.querySelectorAll(
          'input:not([type=checkbox]):not([type=radio]):not([type=hidden]):not([type=range]), textarea, select, [role=combobox]'
        )
        for (const f of Array.from(fields)) {
          if (!shown(f)) continue
          const w = f.getBoundingClientRect().width
          if (w > 960) out.wideStretch.push(`field ${Math.round(w)}px wide: "${nameOf(f)}"`)
        }
        const seen = new Set<Element>()
        const tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
        for (let n = tw.nextNode(); n; n = tw.nextNode()) {
          const host = n.parentElement
          if (!host || seen.has(host) || (n.textContent ?? '').trim().length < 40 || hidden(host))
            continue
          if (host.closest('table, pre, code, [role=grid]')) continue
          const rg = document.createRange()
          rg.selectNodeContents(n)
          const widest = Math.max(0, ...Array.from(rg.getClientRects()).map((b) => b.width))
          if (widest > 960) {
            seen.add(host)
            out.wideStretch.push(
              `text line ${Math.round(widest)}px wide: "${short(n.textContent)}"`
            )
          }
        }
        // A rail (narrow grid column, aside) far from the content beside it.
        const contentEdge = (col: Element, side: 'right' | 'left') => {
          let edge = side === 'right' ? -Infinity : Infinity
          const w = document.createTreeWalker(col, NodeFilter.SHOW_TEXT)
          for (let n = w.nextNode(); n; n = w.nextNode()) {
            if (!(n.textContent ?? '').trim() || !n.parentElement || hidden(n.parentElement))
              continue
            const rg = document.createRange()
            rg.selectNodeContents(n)
            for (const b of Array.from(rg.getClientRects())) {
              if (b.width < 1) continue
              edge = side === 'right' ? Math.max(edge, b.right) : Math.min(edge, b.left)
            }
          }
          for (const c of Array.from(col.querySelectorAll(CONTROL))) {
            if (!shown(c)) continue
            const b = c.getBoundingClientRect()
            edge = side === 'right' ? Math.max(edge, b.right) : Math.min(edge, b.left)
          }
          // Drawn content counts too: a chart, an image or a filled bar (the
          // dashboard's category bars run from the label to the value).
          for (const c of [col, ...Array.from(col.querySelectorAll('*'))]) {
            if (!shown(c)) continue
            const painted =
              c.matches('svg, img, canvas, [role=img], [role=progressbar], [role=meter]') ||
              // a filled leaf or a bar track (24 px high at most), not a card
              // or panel around other content
              ((c.children.length === 0 || c.getBoundingClientRect().height <= 24) &&
                !/^(transparent|rgba\(0, 0, 0, 0\))$/.test(getComputedStyle(c).backgroundColor))
            if (!painted) continue
            const b = c.getBoundingClientRect()
            if (b.width < 8 || b.height < 2) continue
            edge = side === 'right' ? Math.max(edge, b.right) : Math.min(edge, b.left)
          }
          return edge
        }
        for (const grid of Array.from(root.querySelectorAll('*'))) {
          if (tracks(grid) < 2 || !shown(grid)) continue
          // A grid in a capped frame (a settings form, 880 px at every desktop
          // width) is drawn the same at 1440 px as here: it did not stretch.
          // Only a grid wider than the 960 px field cap can push its rail away.
          if (grid.getBoundingClientRect().width <= 960) continue
          const kids = Array.from(grid.children).filter(shown)
          for (const rail of kids) {
            const rr = rail.getBoundingClientRect()
            if (rr.width > 480) continue
            // The nearest content on either side, from every column beside
            // the rail (a bar between a label and its value is content), and
            // only when one of them is the wide content column.
            let wide = false
            let left = -Infinity
            let right = Infinity
            for (const other of kids) {
              if (other === rail) continue
              const or = other.getBoundingClientRect()
              if (or.bottom <= rr.top || or.top >= rr.bottom) continue
              if (or.width >= rr.width * 1.5) wide = true
              if (or.right <= rr.left) left = Math.max(left, contentEdge(other, 'right'))
              else if (or.left >= rr.right) right = Math.min(right, contentEdge(other, 'left'))
            }
            if (!wide) continue
            const gap = Math.min(
              Number.isFinite(left) ? rr.left - left : Infinity,
              Number.isFinite(right) ? right - rr.right : Infinity
            )
            if (Number.isFinite(gap) && gap > 400)
              out.wideStretch.push(
                `rail ${Math.round(gap)}px from its content: "${short(rail.textContent, 30)}"`
              )
          }
        }
      }
    }
    // ---- joined: a field with a button beside it closer than the kit gap.
    // The pinned layer of an element: its nearest sticky or fixed box.
    const pinnedOf = (el: Element): Element | null => {
      for (let a: Element | null = el; a; a = a.parentElement) {
        const p = getComputedStyle(a).position
        if (p === 'sticky' || p === 'fixed') return a
      }
      return null
    }
    for (const root of roots) {
      const fields = Array.from(
        root.querySelectorAll(
          'input:not([type=checkbox]):not([type=radio]):not([type=hidden]), [role=combobox], select, textarea'
        )
      ).filter(shown)
      const buttons = Array.from(root.querySelectorAll('button, a[href], [role=button]')).filter(
        (b) => shown(b) && !b.closest('[role=combobox]')
      )
      for (const f of fields) {
        // The field's frame: the bordered wrapper around an input with an icon.
        let frame: Element = f
        for (let a = f.parentElement; a && a !== root; a = a.parentElement) {
          if (a.querySelector('button, a[href]') && a.contains(f)) break
          if (parseFloat(getComputedStyle(a).borderLeftWidth) > 0) frame = a
          if (a.getBoundingClientRect().width > f.getBoundingClientRect().width + 80) break
        }
        const fr = frame.getBoundingClientRect()
        const fLayer = pinnedOf(f)
        for (const b of buttons) {
          if (frame.contains(b)) continue
          // A sticky or fixed action bar scrolls over the page: a field that
          // passes under it is not beside the bar's buttons (and a pinned
          // field is not beside the page's).
          if (pinnedOf(b) !== fLayer) continue
          const br = b.getBoundingClientRect()
          if (br.bottom <= fr.top + 2 || br.top >= fr.bottom - 2) continue
          const gap =
            br.left >= fr.right - 1
              ? br.left - fr.right
              : fr.left >= br.right - 1
                ? fr.left - br.right
                : -1
          if (gap < 0 || gap >= 7.5) continue
          // One segmented control drawn in one shared frame is meant to touch;
          // two framed controls pressed together are not (/scope: the filter
          // button's border against the search box's).
          const group = b.closest('[role=group], [data-slot*="group"]')
          if (group && group.contains(f) && parseFloat(getComputedStyle(group).borderLeftWidth) > 0)
            continue
          out.joined.push(
            `button ${Math.round(gap)}px from a field: "${nameOf(b)}" | "${nameOf(f)}"`
          )
        }
      }
    }
    // ---- cutMeaning: a text cut by its own ellipsis or line clamp. The
    // ellipsis says something is missing, not what: a status reason, a
    // metric's label or a sentence must show in full (wrap, a shorter plain
    // label). Only a name or title (the row's identity, opened in full one
    // click away) or an element marked `data-cut-tooltip` may end in an
    // ellipsis, and then only with its full text reachable.
    const flat = (s: string | null | undefined) => (s ?? '').replace(/\s+/g, ' ').trim()
    // The full text a pointer, a long press or a screen reader reaches: a
    // title, an aria label or description on the element or around it (up to
    // its table cell or card field), or a tooltip trigger.
    const STOP =
      'td, th, [role=cell], [role=gridcell], [role=columnheader], [data-slot^="mobile-card-"], [data-cut-tooltip]'
    const reachable = (el: Element, full: string): boolean => {
      const want = flat(full).toLowerCase()
      for (let a: Element | null = el, up = 0; a && up < 6; a = a.parentElement, up++) {
        if (a.matches('[data-slot="tooltip-trigger"]')) return true
        for (const attr of ['title', 'aria-label', 'aria-description']) {
          const v = flat(a.getAttribute(attr)).toLowerCase()
          if (v && v.includes(want)) return true
        }
        if (a !== el && a.matches(STOP)) break
      }
      return false
    }
    const cssName = (a: Element) => {
      let p = a.tagName.toLowerCase()
      const slot = a.getAttribute('data-slot')
      const col = a.getAttribute('data-column')
      const kind = a.getAttribute('data-column-kind')
      const role = a.getAttribute('role')
      if (slot) p += `[data-slot="${slot}"]`
      if (col) p += `[data-column="${col}"]`
      // A table cell names its column's kind (the cells carry no id).
      else if (kind && /^(td|th)$/i.test(a.tagName)) p += `[data-column-kind="${kind}"]`
      if (role && !slot) p += `[role=${role}]`
      if (a.id && /^[a-z][\w-]*$/i.test(a.id) && !/^radix/.test(a.id)) p += `#${a.id}`
      const cls = Array.from(a.classList).filter((c) => /^(truncate|line-clamp-\d+)$/.test(c))
      if (cls.length) p += `.${cls.join('.')}`
      return { p, anchored: !!(slot || col || (a.id && !/^radix/.test(a.id))) }
    }
    const selectorOf = (el: Element) => {
      const parts: string[] = []
      for (
        let a: Element | null = el;
        a && a !== document.body && parts.length < 4;
        a = a.parentElement
      ) {
        const { p, anchored } = cssName(a)
        parts.unshift(p)
        if (anchored) break
      }
      return parts.join(' > ')
    }
    // The characters drawn before the cut: laid out inside the box's content
    // edge (an ellipsis) or above its bottom edge (a clamp).
    const visibleText = (el: HTMLElement, clamp: boolean) => {
      const r = el.getBoundingClientRect()
      const cs = getComputedStyle(el)
      const rtl = cs.direction === 'rtl'
      const start = r.left + el.clientLeft + parseFloat(cs.paddingLeft)
      const end = r.left + el.clientLeft + el.clientWidth - parseFloat(cs.paddingRight)
      const bottom = r.top + el.clientTop + el.clientHeight - parseFloat(cs.paddingBottom)
      let shownText = ''
      let seen = 0
      const tw = document.createTreeWalker(el, NodeFilter.SHOW_TEXT)
      const rg = document.createRange()
      for (let n = tw.nextNode(); n && seen < 400; n = tw.nextNode()) {
        const text = n.textContent ?? ''
        for (let i = 0; i < text.length && seen < 400; i++, seen++) {
          rg.setStart(n, i)
          rg.setEnd(n, i + 1)
          const b = rg.getBoundingClientRect()
          // A collapsed space has no box; a letter with none was not drawn
          // (a line past the clamp).
          if (b.width === 0 && b.height === 0) {
            if (/\s/.test(text[i])) {
              shownText += text[i]
              continue
            }
            if (!clamp) return flat(shownText)
            continue
          }
          const inside = clamp
            ? b.bottom <= bottom + 0.5
            : rtl
              ? b.left >= start - 0.5
              : b.right <= end + 0.5
          if (inside) shownText += text[i]
          else if (!clamp) return flat(shownText)
        }
      }
      return flat(shownText)
    }
    // The text's laid-out extent past the content edge (the ellipsis only
    // paints over it): rounding alone never makes a cut.
    const overflowsBox = (el: HTMLElement) => {
      const r = el.getBoundingClientRect()
      const cs = getComputedStyle(el)
      const start = r.left + el.clientLeft + parseFloat(cs.paddingLeft)
      const end = r.left + el.clientLeft + el.clientWidth - parseFloat(cs.paddingRight)
      const rg = document.createRange()
      rg.selectNodeContents(el)
      const boxes = Array.from(rg.getClientRects()).filter((b) => b.width > 0.5)
      return boxes.some((b) => b.right > end + 1 || b.left < start - 1)
    }
    type Cut = { el: Element; sel: string; visible: string; full: string; note: string }
    const cuts: Cut[] = []
    for (const root of roots) {
      for (const node of [root, ...Array.from(root.querySelectorAll('*'))]) {
        if (!(node instanceof HTMLElement)) continue
        if (node.matches('input, textarea, select, option, svg, svg *')) continue
        const cs = getComputedStyle(node)
        const ellipsis =
          cs.textOverflow === 'ellipsis' &&
          !/flex|grid/.test(cs.display) &&
          cs.overflowX !== 'visible' &&
          node.scrollWidth > node.clientWidth
        // A clamped box computes to `flow-root` in current Chromium, not
        // `-webkit-box`: the clamp itself is the sign.
        const clamp =
          !ellipsis &&
          /\d/.test(cs.webkitLineClamp) &&
          cs.overflowY !== 'visible' &&
          node.scrollHeight > node.clientHeight + 1
        if (!ellipsis && !clamp) continue
        const full = flat(node.textContent)
        if (!full || !shown(node)) continue
        if (ellipsis && !overflowsBox(node)) continue
        const visible = visibleText(node, clamp)
        if (visible === full) continue
        const kind = node.closest('[data-column-kind]')?.getAttribute('data-column-kind')
        const optOut = node.closest('[data-cut-tooltip]')
        const reach = reachable(node, full)
        if ((kind === 'name' || optOut) && reach) continue
        const note = optOut
          ? ' (marked data-cut-tooltip, no tooltip or title holds the full text)'
          : kind === 'name'
            ? ' (name column, no tooltip or title holds the full text)'
            : ''
        cuts.push({ el: node, sel: selectorOf(node), visible, full, note })
      }
    }
    // One line per element pattern (a column's cells, a strip's tiles), the
    // first example and the count; an outer box around a reported inner one
    // says the same cut again.
    const inner = cuts.filter((c) => !cuts.some((o) => o !== c && c.el.contains(o.el)))
    const groups = new Map<string, { c: Cut; n: number }>()
    for (const c of inner) {
      const g = groups.get(c.sel)
      if (g) g.n++
      else groups.set(c.sel, { c, n: 1 })
    }
    for (const [sel, { c, n }] of groups)
      out.cutMeaning.push(
        `cut "${short(c.visible, 60)}…" of "${short(c.full, 120)}" at ${sel}${n > 1 ? ` (${n} elements)` : ''}${c.note}`
      )

    // ---- hollowCard: a framed card whose content stops well above its
    // inner bottom edge. Content is what paints: text (its line boxes, not the
    // box that holds it), media and controls, a box with a background or a
    // border, cut to any box that clips it. A fill area (HOLLOW_FILL) is
    // content to its whole box: it is drawn to fill the room on purpose.
    const HOLLOW_FILL = [
      // A chart's plot box (recharts sizes its SVG to it).
      '.recharts-responsive-container',
      // A zoomable canvas (React Flow): its nodes sit where a person put them.
      '.react-flow',
      '[data-layout-canvas]',
      // The shared empty state: it centres itself in the room it is given.
      '[data-slot="empty-state"]',
    ].join(',')
    const MEDIA = /^(IMG|svg|CANVAS|VIDEO|IFRAME|INPUT|TEXTAREA|SELECT|BUTTON)$/
    const clear = (c: string) => /rgba\(0, 0, 0, 0\)|transparent/.test(c)
    const textRange = document.createRange()
    const contentBottom = (box: Element, clipAt: number): number => {
      let bottom = -Infinity
      const walk = (e: Element, clip: number) => {
        const s = getComputedStyle(e)
        if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') return
        const r = e.getBoundingClientRect()
        const big = r.width >= 2 && r.height >= 2
        if (e.matches(HOLLOW_FILL) || MEDIA.test(e.tagName)) {
          if (big) bottom = Math.max(bottom, Math.min(r.bottom, clip))
          return
        }
        if (
          big &&
          (!clear(s.backgroundColor) ||
            parseFloat(s.borderBottomWidth) > 0 ||
            parseFloat(s.borderTopWidth) > 0)
        )
          bottom = Math.max(bottom, Math.min(r.bottom, clip))
        for (const n of Array.from(e.childNodes)) {
          if (n.nodeType !== 3 || !(n.textContent ?? '').trim()) continue
          textRange.selectNodeContents(n)
          const t = textRange.getBoundingClientRect()
          if (t.height > 0) bottom = Math.max(bottom, Math.min(t.bottom, clip))
        }
        const inner = s.overflowY === 'visible' ? clip : Math.min(clip, r.bottom)
        for (const c of Array.from(e.children)) walk(c, inner)
      }
      for (const c of Array.from(box.children)) walk(c, clipAt)
      for (const n of Array.from(box.childNodes)) {
        if (n.nodeType !== 3 || !(n.textContent ?? '').trim()) continue
        textRange.selectNodeContents(n)
        const t = textRange.getBoundingClientRect()
        if (t.height > 0) bottom = Math.max(bottom, Math.min(t.bottom, clipAt))
      }
      return bottom
    }
    const framed = (el: Element) => {
      // A field is not a card (a tall text area is empty until typed in).
      if (el.matches(`input,select,textarea,[role=textbox],[contenteditable],${HOLLOW_FILL}`))
        return false
      if (el.closest('svg, .react-flow, [data-layout-canvas]')) return false
      const s = getComputedStyle(el)
      if (parseFloat(s.borderTopLeftRadius) < 4 && parseFloat(s.borderBottomRightRadius) < 4)
        return false
      if (clear(s.backgroundColor)) return false
      return (['Top', 'Right', 'Bottom', 'Left'] as const).every(
        (k) => parseFloat(s[`border${k}Width`]) > 0 && s[`border${k}Style`] !== 'none'
      )
    }
    type Hollow = { gap: number; height: number; limit: number }
    const measureCard = (el: Element): Hollow => {
      const r = el.getBoundingClientRect()
      const s = getComputedStyle(el)
      const top = r.top + parseFloat(s.borderTopWidth) + parseFloat(s.paddingTop)
      const innerBottom = r.bottom - parseFloat(s.borderBottomWidth) - parseFloat(s.paddingBottom)
      const clipAt = s.overflowY === 'visible' ? Infinity : r.bottom
      const last = Math.max(top, contentBottom(el, clipAt))
      return {
        gap: Math.round(innerBottom - last),
        height: Math.round(r.height),
        limit: Math.max(64, Math.round(r.height * 0.3)),
      }
    }
    // The neighbours in the row the card stands in: it climbs through
    // wrappers it reaches the bottom of (a cell with a heading above the
    // card), then takes the siblings of a grid or row flex box that share its
    // height band.
    const rowNeighbours = (card: Element, root: Element): Element[] => {
      let x: Element = card
      for (let i = 0; i < 8 && x !== root; i++) {
        const p = x.parentElement
        if (!p) break
        const ps = getComputedStyle(p)
        const xr = x.getBoundingClientRect()
        const row =
          /grid/.test(ps.display) || (/flex/.test(ps.display) && !/column/.test(ps.flexDirection))
        if (row) {
          const sibs = Array.from(p.children).filter((c) => {
            if (c === x || !shown(c)) return false
            const cr = c.getBoundingClientRect()
            const band = Math.min(cr.bottom, xr.bottom) - Math.max(cr.top, xr.top)
            const side = cr.right <= xr.left + 2 || cr.left >= xr.right - 2
            return side && band > Math.min(cr.height, xr.height) / 2
          })
          if (sibs.length) return sibs
        }
        const pr = p.getBoundingClientRect()
        const room = pr.bottom - parseFloat(ps.borderBottomWidth) - parseFloat(ps.paddingBottom)
        if (room - xr.bottom > 4) break
        x = p
      }
      return []
    }
    // A neighbour fills the row: the card in it (or the cell itself) is not
    // hollow.
    const fillsRow = (cell: Element) => {
      const cr = cell.getBoundingClientRect()
      const cards = [cell, ...Array.from(cell.querySelectorAll('*'))].filter(
        (e) => Math.abs(e.getBoundingClientRect().bottom - cr.bottom) <= 4 && framed(e)
      )
      if (cards.length) {
        const m = measureCard(cards[0])
        return m.gap <= m.limit
      }
      return cr.bottom - Math.max(cr.top, contentBottom(cell, Infinity)) <= 64
    }
    type HollowHit = { el: Element; sel: string; m: Hollow }
    const hollows: HollowHit[] = []
    for (const root of roots) {
      for (const el of [root, ...Array.from(root.querySelectorAll('*'))]) {
        if (!framed(el) || !shown(el)) continue
        const r = el.getBoundingClientRect()
        if (r.width < 120) continue
        const m = measureCard(el)
        if (m.gap <= m.limit) continue
        if (rowNeighbours(el, root).some(fillsRow)) continue
        hollows.push({ el, sel: selectorOf(el), m })
      }
    }
    const hollowGroups = new Map<string, { h: HollowHit; n: number }>()
    for (const h of hollows) {
      const g = hollowGroups.get(h.sel)
      if (g) g.n++
      else hollowGroups.set(h.sel, { h, n: 1 })
    }
    for (const [sel, { h, n }] of hollowGroups)
      out.hollowCard.push(
        `card ends ${h.m.gap}px below its last content (${h.m.height}px tall, limit ${h.m.limit}px) at ${sel}${n > 1 ? ` (${n} cards)` : ''} "${short(h.el.textContent, 40)}"`
      )

    // ---- The control-shape kinds (owner reports 2026-11-27): a chevron
    // floating mid-control, a queue row's action floating mid-row, a select
    // three lines tall in a 32 px toolbar, a toolbar's buttons cut by the
    // window's edge.
    const rtlOf = (el: Element) => getComputedStyle(el).direction === 'rtl'
    const innerBox = (el: Element) => {
      const r = el.getBoundingClientRect()
      const s = getComputedStyle(el)
      return {
        left: r.left + parseFloat(s.borderLeftWidth) + parseFloat(s.paddingLeft),
        right: r.right - parseFloat(s.borderRightWidth) - parseFloat(s.paddingRight),
      }
    }
    const painted = (el: Element) => {
      const s = getComputedStyle(el)
      return s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0'
    }
    // Horizontal extents of what a box paints: its text line boxes, its svgs
    // and images, and boxes with a background or border, each cut to the box.
    const contentSpans = (box: Element, skip: Element | null) => {
      const spans: { left: number; right: number }[] = []
      const rg = document.createRange()
      const walk = (e: Element) => {
        if (e === skip || !painted(e)) return
        if (e.getAttribute('aria-hidden') === 'true' && e.tagName !== 'svg') return
        if (/^(svg|IMG)$/.test(e.tagName)) {
          const r = e.getBoundingClientRect()
          if (r.width >= 1) spans.push({ left: r.left, right: r.right })
          return
        }
        const s = getComputedStyle(e)
        if (e !== box && (!clear(s.backgroundColor) || parseFloat(s.borderLeftWidth) > 0)) {
          const r = e.getBoundingClientRect()
          if (r.width >= 2 && r.height >= 2) spans.push({ left: r.left, right: r.right })
        }
        for (const n of Array.from(e.childNodes)) {
          if (n.nodeType === 3 && (n.textContent ?? '').trim()) {
            rg.selectNodeContents(n)
            for (const b of Array.from(rg.getClientRects()))
              if (b.width >= 1) spans.push({ left: b.left, right: b.right })
          } else if (n.nodeType === 1) walk(n as Element)
        }
      }
      walk(box)
      return spans
    }

    // ---- deadSpace: a control with a trailing icon (a chevron, a caret: a
    // combobox, a menu or popup button, a button ending in an svg) whose icon
    // stands more than 12 px from the control's inner end, or more than 16 px
    // after the control's text (empty room inside the control: "Target: All"
    // in a box sized for "Known exploited"). Exempt from the second only a
    // control that holds one width by design (`data-hold-width`, a
    // `ToolbarSlot` sized by every value it can show) and a field that fills
    // its column (a form's full-width select: its chevron is at its end).
    const TRAILING =
      '[role=combobox]:not(input), button[aria-haspopup], [role=button][aria-haspopup], [data-slot="select-trigger"], [data-slot="filter-select"], [data-slot="button"], button'
    for (const root of roots) {
      for (const c of Array.from(root.querySelectorAll(TRAILING))) {
        if (!shown(c) || c.closest('.react-flow, [data-layout-canvas]')) continue
        const r = c.getBoundingClientRect()
        if (r.width < 48 || r.height > 64) continue
        const rtl = rtlOf(c)
        // The trailing icon: the icon-sized svg drawn furthest towards the
        // end, with text before it and nothing after it. Found by position,
        // not by markup, so a group (a filter token: its trigger, then an
        // empty room kept for its clear button) is measured as one control.
        const svgs = Array.from(c.querySelectorAll('svg')).filter((g) => {
          if (!painted(g) || hidden(g)) return false
          const gr = g.getBoundingClientRect()
          return gr.width >= 8 && gr.width <= 24
        })
        if (!svgs.length) continue
        const last = svgs.reduce((x, y) => {
          const xr = x.getBoundingClientRect()
          const yr = y.getBoundingClientRect()
          return (rtl ? yr.left < xr.left : yr.right > xr.right) ? y : x
        })
        const icon = last.getBoundingClientRect()
        const others = contentSpans(c, last).filter((sp) => sp.right - sp.left >= 1)
        if (!others.length) continue
        if (others.some((sp) => (rtl ? sp.left < icon.left - 1 : sp.right > icon.right + 1)))
          continue
        const inner = innerBox(c)
        const tail = Math.round(rtl ? icon.left - inner.left : inner.right - icon.right)
        const name = nameOf(c)
        if (tail > 12) {
          out.deadSpace.push(
            `trailing icon ${tail}px from the end of "${name}" (${Math.round(r.width)}px wide)`
          )
          continue
        }
        // A select field may be given a width (a form column, a set toolbar
        // width) with its chevron pinned to its end; a filter token, a menu
        // button or a button hugs what it shows.
        if (c.matches('[data-slot="select-trigger"], [role=combobox]')) continue
        if (c.closest('[data-hold-width]') || c.querySelector('[data-slot="toolbar-slot"]'))
          continue
        const p = c.parentElement
        if (p && painted(p)) {
          const pi = innerBox(p)
          if (r.width >= pi.right - pi.left - 2) continue
        }
        const spans = contentSpans(c, last).filter((s) =>
          rtl ? s.left >= icon.right - 1 : s.right <= icon.left + 1
        )
        if (!spans.length) continue
        const end = rtl
          ? Math.min(...spans.map((s) => s.left))
          : Math.max(...spans.map((s) => s.right))
        const gap = Math.round(rtl ? end - icon.right : icon.left - end)
        if (gap > 16)
          out.deadSpace.push(
            `${gap}px of empty room before the trailing icon of "${name}" (${Math.round(r.width)}px wide)`
          )
      }
    }

    // ---- floatingAction: a list row's action that stands neither at the
    // row's start nor at its end: nothing of the row after it, yet more than
    // 64 px short of the row's inner end ("Validate" in the middle of a
    // 1500 px "Waiting for you" row).
    for (const root of roots) {
      for (const row of Array.from(root.querySelectorAll('li, [role=listitem]'))) {
        if (!shown(row)) continue
        const rr = row.getBoundingClientRect()
        if (rr.width < 480) continue
        const rtl = rtlOf(row)
        const inner = innerBox(row)
        const actions = Array.from(row.querySelectorAll('[data-slot="button"]')).filter(
          (b) => shown(b) && b.closest('li, [role=listitem]') === row
        )
        for (const b of actions) {
          const br = b.getBoundingClientRect()
          const fromEnd = Math.round(rtl ? br.left - inner.left : inner.right - br.right)
          const fromStart = Math.round(rtl ? inner.right - br.right : br.left - inner.left)
          if (fromEnd <= 64 || fromStart <= 64) continue
          // Anything of the row past the action, on the action's line?
          const after = contentSpans(row, b).some((s) => {
            return rtl ? s.right <= br.left + 1 && s.right > inner.left : s.left >= br.right - 1
          })
          if (after) continue
          out.floatingAction.push(
            `action "${nameOf(b)}" floats ${fromEnd}px short of its row's end (${Math.round(rr.width)}px row)`
          )
        }
      }
    }

    // ---- tallControl: a button, select or filter token more than 1.5x as
    // tall as the other controls of its row (a select whose value wrapped
    // onto three lines beside 32 px buttons). The row is the nearest flex or
    // grid box that lays the control out beside others.
    const SHAPED =
      '[data-slot="button"], [data-slot="select-trigger"], [data-slot="filter-select"], [role=combobox]:not(input)'
    for (const root of roots) {
      const ctrls = Array.from(root.querySelectorAll(SHAPED)).filter(
        (c) => shown(c) && !c.parentElement?.closest(SHAPED)
      )
      const seen = new Set<Element>()
      for (const c of ctrls) {
        const r = c.getBoundingClientRect()
        let box: Element | null = c.parentElement
        for (; box && box !== root.parentElement; box = box.parentElement) {
          const s = getComputedStyle(box)
          if (s.display === 'contents') continue
          if (/flex/.test(s.display) && !/column/.test(s.flexDirection)) break
          if (/grid/.test(s.display)) break
        }
        if (!box) continue
        const peers = ctrls.filter((o) => {
          if (o === c || !box!.contains(o)) return false
          const or = o.getBoundingClientRect()
          // A text link drawn as a kit button (variant link) is a line of
          // text, not a control of the row's height.
          if (o.matches('[data-variant="link"]') || or.height < 24) return false
          // Beside it: the two share part of their height band.
          return Math.min(or.bottom, r.bottom) - Math.max(or.top, r.top) > 4
        })
        if (!peers.length) continue
        const hs = peers.map((o) => o.getBoundingClientRect().height).sort((a, b) => a - b)
        const median = hs[Math.floor(hs.length / 2)]
        if (r.height > median * 1.5 && r.height - median > 12 && !seen.has(c)) {
          seen.add(c)
          out.tallControl.push(
            `control "${nameOf(c)}" is ${Math.round(r.height)}px tall beside ${Math.round(median)}px controls`
          )
        }
      }
    }

    // ---- pastEdge: a control drawn past the window's edge, or past the
    // page column's edge, outside a box made to scroll sideways (a table's
    // scroller, the page tab strip, a canvas): the toolbar's "Refresh" and
    // "Display" cut at the right of the window.
    const SIDEWAYS =
      '[data-slot="table-container"], [data-tab-strip], .react-flow, [data-layout-canvas], [data-scroll-x]'
    const content = document.querySelector('#content')
    for (const root of roots) {
      // The page column bounds a page's controls; an overlay (a dialog, a
      // sheet) is bounded by the window only.
      const column = content && content.contains(root) ? content : document.documentElement
      const colBox = column.getBoundingClientRect()
      const edgeR = Math.min(vw, colBox.right)
      const edgeL = Math.max(0, colBox.left)
      for (const c of Array.from(root.querySelectorAll(CONTROL))) {
        const outer = c.parentElement?.closest(CONTROL)
        if (outer && root.contains(outer)) continue
        if (!shown(c) || c.closest(SIDEWAYS)) continue
        // Inside a box of its own that scrolls sideways (a wide preview): a
        // control out of view there is reached by scrolling.
        let scrolls = false
        for (
          let a = c.parentElement;
          a && a !== column && a !== document.body;
          a = a.parentElement
        ) {
          if (
            /auto|scroll/.test(getComputedStyle(a).overflowX) &&
            a.scrollWidth > a.clientWidth + 1
          ) {
            scrolls = true
            break
          }
        }
        if (scrolls) continue
        const r = c.getBoundingClientRect()
        const past = Math.round(Math.max(r.right - edgeR, edgeL - r.left))
        if (past > 1)
          out.pastEdge.push(
            `control "${nameOf(c)}" ${past}px past the ${r.right > edgeR ? (edgeR === vw ? 'window' : 'page column') : 'start'} edge`
          )
      }
    }

    // ---- cellCrowd: in a table row or a list row drawn between lines, a
    // text line or a chip closer than 4 px to the row's ruled top or bottom
    // edge, or across it (a "Ransomware" chip crossing the row's bottom
    // border, owner 2026-11-27). Only an edge with a line on it counts: the
    // row's own border, or its neighbour's border on that side.
    const CHIP =
      '[data-slot="badge"], [data-slot="signal-chip"], [data-slot="status-lozenge"], [data-slot="severity-badge"]'
    const bw = (el: Element | null, side: 'Top' | 'Bottom') => {
      if (!el) return 0
      const s = getComputedStyle(el)
      return s[`border${side}Style`] === 'none' ? 0 : parseFloat(s[`border${side}Width`])
    }
    const crowdRange = document.createRange()
    for (const root of roots) {
      for (const row of Array.from(root.querySelectorAll('tr, [role=row], li'))) {
        if (!shown(row) || row.closest('.react-flow, [data-layout-canvas]')) continue
        // A header row is laid out by its own rules; a row in a sideways
        // scroller still has its own height.
        if (row.closest('thead')) continue
        const rr = row.getBoundingClientRect()
        if (rr.height < 16) continue
        // The row's box: a table row's cells may draw the line.
        const cell = row.matches('tr') ? row.querySelector('td, th') : null
        const ruleTop =
          bw(row, 'Top') > 0 || bw(cell, 'Top') > 0 || bw(row.previousElementSibling, 'Bottom') > 0
        const ruleBottom =
          bw(row, 'Bottom') > 0 ||
          bw(cell, 'Bottom') > 0 ||
          bw(row.nextElementSibling, 'Top') > 0 ||
          // A divide-y list rules every row but the last from above.
          (!!row.nextElementSibling && bw(row.nextElementSibling, 'Top') > 0)
        if (!ruleTop && !ruleBottom) continue
        const boxes: { top: number; bottom: number; what: string }[] = []
        for (const chip of Array.from(row.querySelectorAll(CHIP))) {
          if (!shown(chip) || chip.closest('tr, [role=row], li') !== row) continue
          const r = chip.getBoundingClientRect()
          boxes.push({
            top: r.top,
            bottom: r.bottom,
            what: `chip "${short(chip.textContent, 30)}"`,
          })
        }
        const tw = document.createTreeWalker(row, NodeFilter.SHOW_TEXT)
        for (let n = tw.nextNode(); n; n = tw.nextNode()) {
          const host = n.parentElement
          if (!host || !(n.textContent ?? '').trim() || hidden(host)) continue
          if (host.closest('tr, [role=row], li') !== row || host.closest(CHIP)) continue
          // What is drawn: a line clamp or a clipping box (up to the row)
          // hides the lines past it.
          let clipTop = -Infinity
          let clipBottom = Infinity
          for (let a: Element | null = host; a && a !== row; a = a.parentElement) {
            if (getComputedStyle(a).overflowY !== 'visible') {
              const ar = a.getBoundingClientRect()
              clipTop = Math.max(clipTop, ar.top)
              clipBottom = Math.min(clipBottom, ar.bottom)
            }
          }
          crowdRange.selectNodeContents(n)
          for (const b of Array.from(crowdRange.getClientRects())) {
            if (b.width < 1 || b.height < 1) continue
            const top = Math.max(b.top, clipTop)
            const bottom = Math.min(b.bottom, clipBottom)
            if (bottom - top < 1) continue
            boxes.push({ top, bottom, what: `text "${short(n.textContent, 30)}"` })
          }
        }
        const inTop = rr.top + bw(row, 'Top')
        const inBottom = rr.bottom - bw(row, 'Bottom')
        for (const b of boxes) {
          // Wholly outside the row (a popover anchored to it, a row cut by
          // its scroller): not the row's own content.
          if (b.bottom <= rr.top || b.top >= rr.bottom) continue
          const below = Math.round((inBottom - b.bottom) * 10) / 10
          const above = Math.round((b.top - inTop) * 10) / 10
          if (ruleBottom && below < 4) {
            out.cellCrowd.push(
              `${b.what} ${below < 0 ? `${-below}px past` : `${below}px from`} its row's bottom edge (${Math.round(rr.height)}px row)`
            )
            break
          }
          if (ruleTop && above < 4) {
            out.cellCrowd.push(
              `${b.what} ${above < 0 ? `${-above}px past` : `${above}px from`} its row's top edge (${Math.round(rr.height)}px row)`
            )
            break
          }
        }
      }
    }

    for (const k of Object.keys(out) as (keyof typeof out)[]) out[k] = [...new Set(out[k])]
    return out
  }, scope)
}
