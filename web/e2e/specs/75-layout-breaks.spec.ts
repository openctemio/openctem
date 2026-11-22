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
 * Variants per route: 390x844 en and vi (light), 1440x900, 1280x800 and 1024x768 en; 0 and 1 rows at
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
const LAPTOP = { width: 1280, height: 800 }

/** Lists and pages with phone cards, sheets and long names. */
const CI_ROUTES = [
  // The home: its dashboard snapshot gets long titles and big figures (richData).
  '/',
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
  '/exceptions',
  '/exposures/vulnerabilities',
  '/exposures/vulnerabilities?tab=catalog',
  '/attack-surface/certificates',
  '/attack-surface/changes',
  '/vulnerabilities',
  '/components',
  '/exposures',
  '/scans',
  '/scans/runs',
  '/scans/workflows',
  '/scans/approvals',
  '/sensors',
  '/my-work',
  '/settings/service-accounts',
  '/attack-surface/exposures',
  '/attack-surface/technologies',
  '/remediation/tasks',
  '/remediation/campaigns',
  '/scope',
  '/settings/general',
  '/settings/members',
  '/settings/roles',
  '/settings/audit-log',
  '/settings/api-keys',
  '/settings/security',
  '/settings/scope',
  '/settings/integrations',
  '/settings/risk-scoring',
  '/attack-surface/discovery',
  '/settings/scanning/scan-approval',
  '/settings/sla-policies',
  '/settings/scanning/tool-sources',
  '/settings/teams',
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
/** Presets of the risk scoring page: the known names and one long custom name that must wrap. */
function riskPresets(scen: Scenario) {
  const names = [
    'default',
    'banking',
    'healthcare',
    'ecommerce',
    'government',
    'legacy',
    'regional-payment-processors-and-card-schemes-extended-review',
  ]
  const n = scen === 'empty' ? 0 : scen === 'one' ? 1 : names.length
  return names.slice(0, n).map((name) => ({ name, config: {} }))
}
/** A weighted model with every control on screen: the seed's default model hides most of them. */
function riskSettings() {
  return {
    preset: 'custom',
    score_composition_mode: 'multiply',
    floor_unowned_at_p2: true,
    weights: { exposure: 30, criticality: 25, findings: 30, ctem: 15 },
    exposure_scores: { public: 100, restricted: 70, private: 40, isolated: 10, unknown: 50 },
    exposure_multipliers: { public: 1.5, restricted: 1.2, private: 1, isolated: 0.5, unknown: 1 },
    criticality_scores: { critical: 100, high: 75, medium: 50, low: 25, none: 0 },
    finding_impact: {
      mode: 'severity_weighted',
      per_finding_points: 5,
      finding_cap: 20,
      severity_weights: { critical: 10, high: 7, medium: 4, low: 2, info: 0 },
    },
    ctem_points: {
      enabled: true,
      internet_accessible: 15,
      pii_exposed: 10,
      phi_exposed: 15,
      high_risk_compliance: 10,
      restricted_data: 10,
    },
    risk_levels: { critical_min: 80, high_min: 60, medium_min: 40, low_min: 20 },
  }
}
/**
 * Tool source keys: long source names and tool lists, a set key that was never
 * used, one rotated by a person with a long name, and a source with no key.
 */
function toolSources(scen: Scenario) {
  const sources = [
    {
      id: 'alienvault',
      name: 'AlienVault OTX',
      tools: ['subfinder', 'amass', 'httpx', 'nuclei', 'katana'],
      format: 'key',
      key: {
        set: true,
        last4: 'ab12',
        enabled: true,
        updated_at: '2026-11-10T08:00:00Z',
        updated_by_name: 'Nguyễn Thị Minh Khuê Hoàng Phương Thảo',
        last_used_at: '2026-11-19T21:30:00Z',
      },
    },
    {
      id: 'securitytrails-enterprise-passive-dns',
      name: 'SecurityTrails passive DNS and historical records',
      tools: ['subfinder'],
      format: 'key',
      key: { set: true, last4: '9f0e', enabled: false, updated_at: '2026-10-01T08:00:00Z' },
    },
    {
      id: 'censys',
      name: 'Censys',
      tools: ['subfinder', 'amass'],
      format: 'pair',
      format_hint: 'TOKEN:ORG_ID',
      key: null,
    },
    { id: 'bevigil', name: 'BeVigil', tools: ['subfinder'], format: 'key', key: null },
  ]
  return { sources: sources.slice(0, scen === 'empty' ? 0 : scen === 'one' ? 1 : sources.length) }
}
/** Exception rules with long names, every state and type (the API returns the whole list). */
function suppressions(scen: Scenario) {
  const day = 24 * 60 * 60 * 1000
  const base = {
    tenant_id: 't',
    requested_by: '00000000-0000-4000-8000-000000000001',
    requested_at: new Date(Date.now() - 3 * day).toISOString(),
    created_at: '2026-10-01T08:00:00Z',
    updated_at: '2026-10-01T08:00:00Z',
  }
  const rules = [
    {
      id: 'sup-1',
      name: 'Payments legacy TLS until the migration of the card gateway is finished',
      suppression_type: 'accepted_risk',
      rule_id: 'tls-weak-cipher-suites-accepted-on-legacy-gateways',
      tool_name: 'nuclei',
      status: 'pending',
      expires_at: new Date(Date.now() + 40 * day).toISOString(),
    },
    {
      id: 'sup-2',
      name: 'Test fixtures in example/payments',
      suppression_type: 'false_positive',
      rule_id: 'generic-api-key',
      path_pattern: 'test/fixtures/**',
      status: 'approved',
      approved_by: '00000000-0000-4000-8000-000000000002',
      expires_at: new Date(Date.now() + 5 * day).toISOString(),
    },
    {
      id: 'sup-3',
      name: 'Kiosk Windows 7 build',
      suppression_type: 'wont_fix',
      tool_name: 'network-scanner',
      status: 'expired',
      expires_at: '2026-11-01T00:00:00Z',
    },
    {
      id: 'sup-4',
      name: 'Old marketing site on www.example.com',
      suppression_type: 'false_positive',
      path_pattern: 'legacy/**',
      status: 'rejected',
      rejected_by: '00000000-0000-4000-8000-000000000002',
      rejection_reason: 'Not funded',
    },
  ].map((r) => ({ ...base, ...r }))
  const data = rules.slice(0, scen === 'empty' ? 0 : scen === 'one' ? 1 : rules.length)
  return { data, total: data.length }
}

/** Import and run receipts with long tool names and big counts. */
function receipts(scen: Scenario) {
  const counts = (k: number) => ({
    created: 12 * k,
    updated: 1280 * k,
    reactivated: 3,
    closed: 40 * k,
    skipped: 9,
    failed: 1,
    suppressed: 4,
  })
  const kinds = ['upload', 'scan_run', 'command', 'ci_run', 'connector', 'sensor', 'platform']
  const all = Array.from({ length: 25 }, (_, i) => ({
    id: `rcpt-${i}`,
    status: ['completed', 'processing', 'failed', 'queued'][i % 4],
    source: { kind: kinds[i % kinds.length], ref: `run-${i}` },
    tool: i % 5 === 4 ? '' : ['nuclei', 'network vulnerability scanner export', 'trivy'][i % 3],
    received: 18402 - i,
    counts: counts(i + 1),
    started_at: new Date(Date.now() - (i + 1) * 3600_000).toISOString(),
  }))
  const data = all.slice(0, scen === 'empty' ? 0 : scen === 'one' ? 1 : all.length)
  const total = scen === 'rich' ? 380 : data.length
  return {
    data,
    total,
    page: 1,
    per_page: 50,
    total_pages: Math.max(1, Math.ceil(total / 50)),
    totals: {
      receipts: total,
      received: 18402,
      created: 611,
      updated: 15002,
      reactivated: 12,
      closed: 388,
      skipped: 300,
      failed: 57,
      suppressed: 40,
    },
  }
}

/** Certificates with long subjects, a wildcard, a self-signed one and every status. */
function certificates(scen: Scenario) {
  const day = 86_400_000
  const rows = Array.from({ length: 25 }, (_, i) => {
    const status = (['expired', 'expiring_soon', 'ok', 'ok', 'unknown'] as const)[i % 5]
    const days = status === 'expired' ? -(i + 3) : status === 'expiring_soon' ? i + 2 : 90 + i
    return {
      asset_id: `00000000-0000-4000-8000-0000000c${String(i).padStart(4, '0')}`,
      name: `cert-${i}`,
      subject_cn:
        i % 4 === 0
          ? `payments-gateway-eu-west-production-cluster-${i}.internal.example.com`
          : i % 4 === 1
            ? '*.example.com'
            : `www${i}.example.com`,
      issuer_cn:
        i % 3 === 0 ? 'Example Trust Services Issuing CA 2 (Extended Validation)' : 'Example CA R3',
      issuer_org: i % 3 === 0 ? 'Example Trust Services Limited' : 'Example Certificate Authority',
      fingerprint_sha256: `${'ab12cd34'.repeat(8).slice(0, 63)}${i % 10}`,
      not_before: new Date(Date.now() - (300 - days) * day).toISOString(),
      not_after: new Date(Date.now() + days * day).toISOString(),
      status,
      days_to_expiry: days,
      is_self_signed: i % 7 === 3,
      is_wildcard: i % 4 === 1,
      first_seen: new Date(Date.now() - (i + 1) * 5 * 3600_000).toISOString(),
      last_seen: new Date(Date.now() - i * 3600_000).toISOString(),
    }
  })
  const data = rows.slice(0, scen === 'empty' ? 0 : scen === 'one' ? 1 : rows.length)
  return { data, total: scen === 'rich' ? 312 : data.length, page: 1, per_page: 20 }
}
function certificateStats(scen: Scenario) {
  if (scen === 'empty') return { total: 0, expired: 0, expiring_soon: 0, ok: 0, unknown: 0 }
  return { total: 312, expired: 41, expiring_soon: 18, ok: 240, unknown: 13 }
}

/** Attack surface changes of every kind, with long asset names and values. */
function easmChanges(scen: Scenario) {
  const kinds = [
    'dns_dangling',
    'exposure_new',
    'port_opened',
    'host_added',
    'cert_expiring',
    'cert_changed',
    'dns_changed',
    'tech_changed',
    'port_closed',
    'host_removed',
    'future_kind',
  ]
  const items = Array.from({ length: 24 }, (_, i) => ({
    id: `chg-${i}`,
    kind: kinds[i % kinds.length],
    asset_id: i % 6 === 5 ? '' : `00000000-0000-4000-8000-0000000d${String(i).padStart(4, '0')}`,
    asset_name:
      i % 6 === 5
        ? ''
        : i % 3 === 0
          ? `customer-portal-staging-eu-central-edge-${i}.internal.example.com`
          : `host${i}.example.com`,
    severity: i % 4 === 1 ? 'high' : undefined,
    exposure_id: i % 4 === 1 ? `exp-${i}` : undefined,
    new: i % 4 === 1 ? 'Exposed administration interface without authentication' : undefined,
    added: i % 5 === 2 ? ['443/tcp', '8443/tcp', '9200/tcp'] : [],
    removed: i % 5 === 3 ? ['80/tcp'] : [],
    at: new Date(Date.now() - (i + 1) * 2 * 3600_000).toISOString(),
  }))
  const data = items.slice(0, scen === 'empty' ? 0 : scen === 'one' ? 1 : items.length)
  return {
    items: data,
    total: data.length,
    counts: Object.fromEntries(
      kinds.slice(0, 10).map((k, i) => [k, scen === 'empty' ? 0 : 3 + i * 11])
    ),
    next_cursor: scen === 'rich' ? 'cursor-2' : undefined,
  }
}

const ROUTE_DATA: Record<string, { url: string; body: (scen: Scenario) => unknown }[]> = {
  '/settings/risk-scoring': [
    { url: '**/api/v1/tenants/*/settings/risk-scoring/presets', body: riskPresets },
    { url: '**/api/v1/tenants/*/settings/risk-scoring', body: riskSettings },
  ],
  '/settings/scanning/scan-approval': [
    {
      url: '**/api/v1/organization/settings/scan-governance',
      body: scanGovernance,
    },
  ],
  '/settings/scanning/tool-sources': [{ url: '**/api/v1/tool-sources', body: toolSources }],
  '/exceptions': [{ url: '**/api/v1/suppressions', body: suppressions }],
  '/findings/imports': [{ url: '**/api/v1/findings/imports?*', body: receipts }],
  '/attack-surface/certificates': [
    { url: '**/api/v1/attack-surface/certificates?*', body: certificates },
    { url: '**/api/v1/attack-surface/certificates/stats*', body: certificateStats },
  ],
  '/attack-surface/changes': [{ url: '**/api/v1/easm/changes?*', body: easmChanges }],
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
  '/scans/runs',
  '/attack-surface/technologies',
])

/**
 * Pages whose table action buttons are cut by the table scroller's edge at
 * 1024 px (/exposures "Actions for ...", /sensors "Jobs", /settings/audit-log
 * "Result"), found when the sideways strip and scroller checks were added
 * (owner report 2026-11-20). Only the `clipped` lines about a sideways strip or
 * a scroller's edge are skipped for them. Each pins its actions and leaves this
 * list; it only shrinks, and a route not on it fails on its first such line.
 * A page tab strip is not debt: the shared strip scrolls with an edge fade
 * (owner 2026-11-21).
 */
const SIDEWAYS_DEBT = new Set([
  '/sensors', // its Jobs table only; the tab strip is the shared one
  '/exposures',
  '/settings/audit-log',
])
const SIDEWAYS_LINE = /sideways strip|scroller's edge/

/**
 * Pages whose table must fit its frame at every width: a column is dropped,
 * never cut off or scrolled sideways (owner report 2026-11-20, tool source keys).
 */
const NO_SIDE_SCROLL = new Set(['/settings/scanning/tool-sources'])

/** Scrolling frames inside main that hold more than they show. */
async function sideScrolling(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    [...document.querySelectorAll('main *')]
      .filter((el) => {
        const o = getComputedStyle(el).overflowX
        return (o === 'auto' || o === 'scroll') && el.scrollWidth > el.clientWidth + 1
      })
      .map((el) => `${el.tagName.toLowerCase()} ${el.scrollWidth}>${el.clientWidth}`)
  )
}

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
    { tag: 'l-en', ...LAPTOP, lang: 'en', theme: 'light', scen: 'rich' },
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
  // LAYOUT_SWEEP_ONLY=d-en,l-en,t-en runs just those variants (desktop widths of every route).
  const only = process.env.LAYOUT_SWEEP_ONLY?.split(',').filter(Boolean)
  return only ? v.filter((x) => only.includes(x.tag)) : v
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
        for (const extra of ROUTE_DATA[route] ?? []) {
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
        if (NO_SIDE_SCROLL.has(route) && !v.overlay) {
          expect.soft(await sideScrolling(page), `${route} ${v.tag}: side scroll`).toEqual([])
        }
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
          const lines =
            kind === 'clipped' && SIDEWAYS_DEBT.has(route)
              ? found[kind].filter((l) => !SIDEWAYS_LINE.test(l))
              : found[kind]
          expect.soft(lines, `${route} ${tag}: ${kind}`).toEqual([])
        }
      }
    })
  }
})

/**
 * A web origin's Paths tab (the tree from 1024 px, the drill-down list on a
 * phone) and its endpoint sheet, with tree data that is hard on the layout:
 * long segments, variable segments, five-digit counts, out-of-scope marks and
 * a long endpoint path. The origin is created through the API; its levels are
 * served by route mocks, so the check needs no crawl.
 */
const LONG = 'getting-started-with-your-account-and-first-order-history'
function pathsLevel(path: string) {
  const at = (p: string) => (path === '/' ? `/${p}` : `${path}/${p}`)
  const folder = (name: string, i: number) => ({
    name,
    path: at(name),
    param: name.startsWith('{'),
    endpoints: 10 ** (i % 5) + i,
    out_of_scope: i % 3 === 0 ? 2 : 0,
    findings: i % 2 ? 12_345 : 0,
    top_severity: i % 4 === 1 ? 'critical' : i % 2 ? 'high' : undefined,
    has_folders: i % 2 === 0,
  })
  const endpoint = (method: string, p: string, i: number) => ({
    id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
    origin_asset_id: 'x',
    origin: 'https://layout.example.com',
    method,
    path_template: p,
    path_hash: 'h',
    kind: 'api',
    sources: ['crawl'],
    example_path: p,
    last_status: [200, 403, 302][i % 3],
    content_type: 'application/vnd.example.order-history+json; charset=utf-8',
    auth_state: ['none', 'required', 'unknown'][i % 3],
    technologies: [],
    labels: [],
    state: 'active',
    in_scope: i % 4 !== 0,
    param_count: i,
    first_seen_at: new Date(Date.now() - 9e8).toISOString(),
    last_seen_at: new Date(Date.now() - 3.6e6 * i).toISOString(),
    finding_count: i % 2 ? 1234 : 0,
    top_severity: i % 2 ? 'critical' : undefined,
  })
  const names = ['api', 'admin', '{int}', LONG, 'static', '{uuid}', 'account', 'docs']
  return {
    path,
    totals: {
      recorded: 4999,
      endpoints: 4321,
      hidden: 678,
      out_of_scope: 12,
      findings: 12_345,
      unrecorded_findings: 3,
      top_severity: 'critical',
      origin_findings: 7,
      capped: false,
    },
    folders: names.map(folder),
    folders_truncated: false,
    endpoints: ['GET', 'POST', 'DELETE', 'OPTIONS', 'PATCH'].map((m, i) =>
      endpoint(m, at(i % 2 ? `${LONG}/{int}/attachments/{uuid}/download` : 'orders/{int}'), i)
    ),
    endpoint_total: 5,
    page: 1,
    per_page: 50,
    node_findings: [
      {
        id: '00000000-0000-4000-8000-000000000001',
        title: `SQL injection in the order history export of ${LONG}`,
        severity: 'critical',
        status: 'new',
        path: `/api/v1/${LONG}/{int}`,
      },
    ],
    node_finding_total: 1,
  }
}

test.describe(
  'Layout breaks: web origin Paths',
  { tag: ['@assets', '@attack-surface', '@phone'] },
  () => {
    test('/assets/[id]?tab=paths', async ({ page, baseURL }, testInfo) => {
      test.setTimeout(240_000)
      await page.goto('/assets', { timeout: 60_000 })
      const created = await page.evaluate(async () => {
        const csrf = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/)?.[1] ?? ''
        const res = await fetch('/api/v1/assets', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf) },
          body: JSON.stringify({
            name: `https://layout-${Date.now()}.example.com`,
            type: 'service',
            sub_type: 'http',
            criticality: 'medium',
          }),
        })
        return { status: res.status, body: await res.json().catch(() => null) }
      })
      const id = (created.body as { id?: string } | null)?.id
      test.skip(!id, `could not create a web origin: ${created.status}`)
      const report: Record<string, Breaks | string> = {}
      const route = `/assets/${id}?tab=paths`
      const paths: [string, string][] = [
        ['root', route],
        ['level', `${route}&path=${encodeURIComponent('/api/{int}')}`],
      ]
      for (const v of variants().filter(
        (x) => x.scen === 'rich' && (!x.overlay || x.overlay === 'detail')
      )) {
        for (const [name, url] of paths) {
          await page.unrouteAll({ behavior: 'ignoreErrors' })
          await prepare(page, v, baseURL!)
          await page.route('**/api/v1/assets/*/web-paths**', (r) =>
            r.fulfill({
              json: pathsLevel(new URL(r.request().url()).searchParams.get('path') ?? '/'),
            })
          )
          await page.route('**/api/v1/web-endpoints/*', (r) =>
            r.fulfill({ json: { ...pathsLevel('/api').endpoints[1], origin_asset_id: id } })
          )
          await page.route('**/api/v1/web-endpoints/*/parameters', (r) =>
            r.fulfill({
              json: {
                data: [
                  {
                    location: 'query',
                    name: 'redirect_uri_for_the_order_history_export',
                    required: true,
                    risk_hints: ['ssrf_candidate', 'redirect'],
                    sources: ['crawl'],
                  },
                ],
              },
            })
          )
          await page.goto(url, { timeout: 60_000 }).catch(() => {})
          await settle(page)
          let scope = 'main'
          if (v.overlay) {
            // The endpoint sheet: a phone list row, or a table row.
            const row = page.locator('main [data-testid=path-drill] button, main tbody tr').first()
            if (!(await row.count())) {
              report[`${name}-${v.tag}`] = 'no such overlay'
              continue
            }
            await row.click().catch(() => {})
            await page
              .locator('[role=dialog]:visible')
              .last()
              .waitFor({ timeout: 5_000 })
              .catch(() => {})
            await page.waitForTimeout(400)
            scope = '[role=dialog]'
          }
          const found = await findBreaks(page, { scope, vi: v.lang === 'vi' })
          report[`${name}-${v.tag}`] = found
          if (OUT || formatBreaks(found).length) {
            await keep(testInfo, `asset-paths-${name}__${v.tag}.png`, await page.screenshot())
          }
          if (v.overlay) await page.keyboard.press('Escape').catch(() => {})
        }
      }
      await keep(testInfo, 'asset-paths.json', JSON.stringify(report, null, 1))
      for (const [tag, found] of Object.entries(report)) {
        if (typeof found === 'string') continue
        for (const kind of BREAK_KINDS)
          expect.soft(found[kind], `paths ${tag}: ${kind}`).toEqual([])
      }
    })
  }
)

/**
 * Detail pages on the shared detail kit (header, page tabs, overlays): a
 * record made through the API, or served by route mocks with long names, at
 * 390 px (light, dark, en, vi), 1024 and 1440 px, plus the header's More menu
 * on a phone.
 */
const DETAIL_VARIANTS: Variant[] = [
  { tag: 'p-en', ...PHONE, lang: 'en', theme: 'light', scen: 'rich' },
  { tag: 'p-vi', ...PHONE, lang: 'vi', theme: 'light', scen: 'rich' },
  { tag: 'p-en-dark', ...PHONE, lang: 'en', theme: 'dark', scen: 'rich' },
  { tag: 't-en', ...TABLET, lang: 'en', theme: 'light', scen: 'rich' },
  { tag: 't-vi', ...TABLET, lang: 'vi', theme: 'light', scen: 'rich' },
  { tag: 'd-en', ...DESKTOP, lang: 'en', theme: 'light', scen: 'rich' },
  { tag: 'd-vi', ...DESKTOP, lang: 'vi', theme: 'light', scen: 'rich' },
  { tag: 'p-ov-more', ...PHONE, lang: 'en', theme: 'light', scen: 'rich', overlay: 'rowmenu' },
]
const DETAIL_MORE = 'main [data-slot="detail-more"] button:visible'

const SYNTH_CVE = 'CVE-2024-3094'
function cveExposure() {
  return {
    cve_id: SYNTH_CVE,
    in_catalog: true,
    verdict: 'confirmed',
    findings: {
      total: 31,
      active: 27,
      by_status: { new: 9, confirmed: 10, in_progress: 8, resolved: 4 },
      by_priority: { P0: 3, P1: 8, P2: 16 },
      worst_priority: 'P0',
      in_task: 18,
      not_in_task: 9,
    },
    assets: { impacted: 14, crown_jewels: 1, internet_facing: 3, with_findings: 14 },
    possible: { assets: 5, products: [`xz-utils-${LONG}`] },
    not_affected: { assets: 22, products: ['xz-utils'] },
    components: [
      {
        product_id: 'p1',
        name: `xz-utils-${LONG}`,
        purl: `pkg:deb/debian/xz-utils-${LONG}@5.6.0`,
        version: '5.6.0',
        fixed_versions: ['5.6.2'],
        recommended_fix: '5.6.2',
        assets: 12,
        active_findings: 23,
      },
    ],
    upgrades: [
      {
        product_id: 'p1',
        name: `xz-utils-${LONG}`,
        target: '5.6.2',
        major_change: false,
        fixes_findings: 23,
        on_assets: 12,
        no_fix_findings: 0,
      },
    ],
    sources: [
      { name: 'Vulnerability scan', source: 'scan', assets: 11 },
      { name: `Component inventory of ${LONG}`, source: 'sbom', assets: 6 },
    ],
    single_source_assets: 4,
    timeline: {
      first_seen_at: '2026-10-02T08:00:00Z',
      last_seen_at: '2026-11-18T08:00:00Z',
      last_fixed_at: '2026-11-06T08:00:00Z',
      fixed: 41,
      reopened: 2,
      last_reopened_at: '2026-11-02T08:00:00Z',
    },
    intel: {
      aliases: [{ id: 'GHSA-rxwq-x6h5-x525', source: 'ghsa', synced_at: '2026-11-18T08:00:00Z' }],
      cwes: ['CWE-506'],
      feeds: [{ source: 'kev', last_sync_at: '2026-11-20T08:00:00Z', status: 'ok' }],
    },
    epss_trend: [
      { date: '2026-11-01', score: 0.7 },
      { date: '2026-11-15', score: 0.84 },
    ],
  }
}
function cveCatalog() {
  return {
    id: '00000000-0000-4000-8000-0000000000c1',
    cve_id: SYNTH_CVE,
    title: `Malicious code in the release archives of a compression library used by ${LONG}`,
    description: `The upstream release archives carry code that changes the build of ${LONG}.`,
    severity: 'critical',
    cvss_score: 10,
    epss_score: 0.84,
    exploit_available: true,
    exploit_maturity: 'functional',
    fixed_versions: ['5.6.2'],
    published_at: '2024-03-29T00:00:00Z',
    status: 'open',
    risk_score: 95,
  }
}
function cveAssets() {
  return {
    data: Array.from({ length: 3 }, (_, i) => ({
      asset_id: `00000000-0000-4000-8000-00000000a00${i}`,
      name: `build-${i}.${LONG}.example.com`,
      asset_type: 'host',
      criticality: 'high',
      crown_jewel: i === 0,
      internet_facing: i < 2,
      owner: 'Platform team',
      open_findings: 3,
      total_findings: 4,
      worst_priority: 'P0',
      worst_severity: 'critical',
      last_seen_at: '2026-11-18T08:00:00Z',
    })),
    total: 3,
    page: 1,
    per_page: 20,
    total_pages: 1,
  }
}

interface DetailCase {
  name: string
  tabs: string[]
  /** The page's URL, made in the browser (an API create) or a fixed one; null skips. */
  url: (page: Page) => Promise<string | null>
  mocks?: { url: string; body: () => unknown }[]
}

const DETAIL_CASES: DetailCase[] = [
  {
    name: 'pentest-campaign',
    tabs: ['overview', 'findings', 'scope', 'team'],
    url: async (page) => {
      await page.goto('/pentest/campaigns', { timeout: 60_000 })
      const id = await page.evaluate(async (long) => {
        const csrf = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/)?.[1] ?? ''
        const res = await fetch('/api/v1/pentest/campaigns', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf) },
          body: JSON.stringify({
            name: `Payments API of ${long}, fourth quarter retest`,
            client_name: `Example Holdings, the regional payments unit of ${long}`,
            methodology: 'OWASP testing guide',
            objectives: ['Reach card data', 'Bypass authorization'],
            tags: ['pci', 'api'],
            targets: ['web_app', 'api'],
          }),
        })
        const body = (await res.json().catch(() => null)) as { id?: string } | null
        return body?.id ?? null
      }, LONG)
      return id ? `/pentest/campaigns/${id}` : null
    },
  },
  {
    name: 'vulnerability',
    tabs: ['summary', 'where', 'remediation', 'intel', 'timeline'],
    url: async () => `/vulnerabilities/${SYNTH_CVE}`,
    mocks: [
      { url: `**/api/v1/vulnerability-exposures/${SYNTH_CVE}/assets**`, body: cveAssets },
      { url: `**/api/v1/vulnerability-exposures/${SYNTH_CVE}`, body: cveExposure },
      { url: `**/api/v1/vulnerabilities/cve/${SYNTH_CVE}`, body: cveCatalog },
    ],
  },
]

test.describe(
  'Layout breaks: detail pages',
  { tag: ['@phone', '@pentest', '@vulnerabilities'] },
  () => {
    test.describe.configure({ mode: 'parallel' })
    for (const c of process.env.LAYOUT_SWEEP_ROUTES ? [] : DETAIL_CASES) {
      test(`detail ${c.name}`, async ({ page, baseURL }, testInfo) => {
        test.setTimeout(FULL ? 600_000 : 300_000)
        const route = await c.url(page)
        test.skip(!route, `could not make a ${c.name} record`)
        const report: Record<string, Breaks | string> = {}
        for (const v of DETAIL_VARIANTS) {
          await page.unrouteAll({ behavior: 'ignoreErrors' })
          await prepare(page, v, baseURL!)
          for (const m of c.mocks ?? []) {
            await page.route(m.url, (r) =>
              r.request().method() === 'GET' ? r.fulfill({ json: m.body() }) : r.fallback()
            )
          }
          // Every tab at the phone widths in en; the first tab elsewhere.
          const tabs = v.tag === 'p-en' || v.tag === 'p-en-dark' ? c.tabs : c.tabs.slice(0, 1)
          for (const tab of tabs) {
            const key = c.name === 'pentest-campaign' ? 'view' : 'tab'
            await page.goto(`${route}?${key}=${tab}`, { timeout: 60_000 }).catch(() => {})
            await settle(page)
            let scope = 'main'
            if (v.overlay) {
              const more = page.locator(DETAIL_MORE).first()
              if (!(await more.count())) {
                report[`${tab}-${v.tag}`] = 'no such overlay'
                continue
              }
              await more.click().catch(() => {})
              await page.waitForTimeout(400)
              scope = '[role=dialog], [role=menu], [data-slot="drawer-content"]'
            }
            const found = await findBreaks(page, { scope, vi: v.lang === 'vi' })
            report[`${tab}-${v.tag}`] = found
            if (OUT || formatBreaks(found).length) {
              await keep(
                testInfo,
                `detail-${c.name}-${tab}__${v.tag}.png`,
                await page.screenshot({ fullPage: !v.overlay })
              )
            }
            if (v.overlay) await page.keyboard.press('Escape').catch(() => {})
          }
        }
        await keep(testInfo, `detail-${c.name}.json`, JSON.stringify(report, null, 1))
        for (const [tag, found] of Object.entries(report)) {
          if (typeof found === 'string') continue
          for (const kind of BREAK_KINDS)
            expect.soft(found[kind], `${c.name} ${tag}: ${kind}`).toEqual([])
        }
      })
    }
  }
)

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
