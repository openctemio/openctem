import { sidebarData } from '@/config/sidebar-data'
import { ACCOUNT_NAV } from '@/config/account-nav'
import { settingsNavItems } from '@/config/settings-nav'
import * as sectionTabs from '@/config/section-tabs'

/**
 * Breadcrumb labels come from the places pages are named, with the same i18n
 * key, so the last crumb always says what the page heading or its active tab
 * says, in the reader's language: a page's own title (PATH_LABELS), the tab
 * strip of a section (config/section-tabs.ts), then the navs (main sidebar and
 * settings rail). Section roots and sub-pages no nav names use FALLBACK_LABELS.
 * `__tests__/breadcrumb-heading.test.ts` fails on a page route whose crumb has
 * no key in en and vi.
 */

type NavNode = { id?: string; title?: string; url?: string; items?: NavNode[] }

/** The i18n key the main sidebar renders an item's title with (nav-group.tsx). */
function navItemKey(title: string): string {
  return `nav.item.${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
}

function collect(
  nodes: NavNode[] | undefined,
  into: Map<string, string>,
  keys: Map<string, string>,
  keyOf: (n: NavNode) => string | undefined
) {
  for (const n of nodes ?? []) {
    if (n.url && n.title && !into.has(n.url)) {
      into.set(n.url, n.title)
      const key = keyOf(n)
      if (key) keys.set(n.url, key)
    }
    collect(n.items, into, keys, keyOf)
  }
}

/** Sidebar titles by URL, and the i18n key each title is rendered with. */
const SIDEBAR_KEYS = new Map<string, string>()
const SIDEBAR_LABELS: Map<string, string> = (() => {
  const map = new Map<string, string>()
  for (const group of sidebarData.navGroups as NavNode[]) {
    collect(group.items, map, SIDEBAR_KEYS, (n) => (n.title ? navItemKey(n.title) : undefined))
  }
  // Settings pages live in the settings rail, not the main sidebar.
  collect(settingsNavItems as NavNode[], map, SIDEBAR_KEYS, (n) =>
    n.id ? `settings.item.${n.id}` : undefined
  )
  // The account area has its own navigation, named the way its tabs are.
  collect(ACCOUNT_NAV as unknown as NavNode[], map, SIDEBAR_KEYS, (n) =>
    n.id ? `account.area.nav.${n.id}` : undefined
  )
  return map
})()

type Named = { label: string; key: string }

/**
 * Menu titles that only make sense inside their menu group ("Overview"), or
 * that name a section's index page ("All integrations"): as a crumb, the
 * section's own name reads better.
 */
const GENERIC_TITLES = new Set(['Overview', 'All', 'All integrations'])

/**
 * Pages no nav or tab strip names, by full path: the label and key of the
 * page's own heading (its `PageHeader` title), so crumb and heading agree.
 */
const PATH_LABELS: Record<string, Named> = {
  // About > Open-source licenses (reached from Help > About).
  '/about/licenses': { label: 'Open-source licenses', key: 'nav.crumb.licenses' },
  '/activate': { label: 'Approve a sensor', key: 'sensors.activate.title' },
  '/attack-surface/external': {
    label: 'External attack surface',
    key: 'attackSurface.external.title',
  },
  '/ci-cd/github-app/callback': {
    label: 'GitHub App installation',
    key: 'scans.ci.callback.title',
  },
  '/settings/scanning/content': {
    label: 'Scanner content',
    key: 'sensors.contentPolicy.page.title',
  },
  '/control-testing': { label: 'Control testing', key: 'validation.controlTesting.title' },
  '/controls': { label: 'Compensating controls', key: 'validation.controls.title' },
  '/dashboards': { label: 'Dashboards', key: 'dashboards.manage.title' },
  '/findings/approvals': { label: 'Approval requests', key: 'findings.approvals.title' },
  '/findings/imports': { label: 'Imports', key: 'findings.receiptHistory.title' },
  '/findings/triage': { label: 'Triage', key: 'findings.triageMode.title' },
  '/pentest/findings': { label: 'Findings', key: 'nav.item.findings' },
  '/insights/ctem-maturity': { label: 'CTEM maturity', key: 'insights.maturity.title' },
  '/notifications': { label: 'Notifications', key: 'settings.notifications.title' },
  '/programs/new': { label: 'Import program', key: 'programs.new.title' },
  '/scoping': { label: 'Scoping', key: 'scoping.overview.title' },
  '/settings/asset-sources': { label: 'Asset sources', key: 'assetSources.title' },
  '/settings/integrations/notifications/history': {
    label: 'Notification events',
    key: 'notificationChannels.history.title',
  },
  '/settings/integrations/notifications/outbox': {
    label: 'Notification queue',
    key: 'notificationChannels.outbox.title',
  },
  '/settings/integrations/scm': { label: 'SCM connections', key: 'scmIntegration.page.title' },
  '/settings/integrations/ticketing': {
    label: 'Ticketing',
    key: 'ticketingIntegration.page.title',
  },
  '/settings/pentest/checklists': { label: 'Checklists', key: 'pentestChecklists.page.title' },
  '/settings/pentest/report-templates': {
    label: 'Report templates',
    key: 'pentest.reportTemplates.title',
  },
  '/settings/pentest/templates': { label: 'Pentest methodology', key: 'settings.pentest.title' },
  '/settings/tenant': { label: 'Organization', key: 'settings.group.organization' },
  '/settings/tenant/create': { label: 'Create organization', key: 'settings.createTeam.title' },
  '/threat-intel': { label: 'Threat intelligence', key: 'threatIntel.title' },
  '/validation': { label: 'Validation', key: 'validation.overview.title' },
}

/** Tab names of every section tab strip and attention queue, by URL. */
const TAB_LABELS: Map<string, Named> = (() => {
  const map = new Map<string, Named>()
  for (const value of Object.values(sectionTabs)) {
    if (!Array.isArray(value)) continue
    for (const tab of value as { href?: unknown; label?: unknown; labelKey?: unknown }[]) {
      if (typeof tab?.href !== 'string' || typeof tab.label !== 'string') continue
      if (typeof tab.labelKey !== 'string' || GENERIC_TITLES.has(tab.label)) continue
      if (!map.has(tab.href)) map.set(tab.href, { label: tab.label, key: tab.labelKey })
    }
  }
  return map
})()

/** Segments that are not sidebar entries themselves (section roots, sub-pages). */
const FALLBACK_LABELS: Record<string, string> = {
  about: 'About',
  assets: 'Asset inventory',
  settings: 'Settings',
  admin: 'Administration',
  integrations: 'Integrations',
  'access-control': 'Access control',
  scanning: 'Scanning',
  account: 'Account',
  insights: 'Insights',
  pentest: 'Penetration testing',
  new: 'New',
  edit: 'Edit',
  builder: 'Builder',
  api: 'API',
  'api-keys': 'API keys',
  'service-accounts': 'Service accounts',
  cicd: 'CI/CD',
  'github-app': 'GitHub App',
  siem: 'SIEM',
  scm: 'SCM',
  saml: 'SAML',
  scim: 'SCIM',
  mcp: 'MCP',
  sla: 'SLA',
  sbom: 'SBOM',
  mttr: 'MTTR',
}

/** "attack-surface" -> "Attack surface" (sentence case, not Title Case). */
function humanize(segment: string): string {
  const words = segment.replace(/[-_]+/g, ' ').trim()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

/** Label for the breadcrumb item at `path` whose last segment is `segment`. */
export function breadcrumbLabel(path: string, segment: string): string {
  const own = PATH_LABELS[path] ?? TAB_LABELS.get(path)
  if (own) return own.label
  const fromSidebar = SIDEBAR_LABELS.get(path)
  if (fromSidebar && !GENERIC_TITLES.has(fromSidebar)) return fromSidebar
  return FALLBACK_LABELS[segment] ?? humanize(segment)
}

/**
 * The i18n key for the same label, so the trail speaks the reader's language:
 * the key the page heading, its tab, the sidebar or the settings rail renders
 * the page with, else `nav.crumb.<segment>` for the section names above.
 * Undefined for a segment with no known name (it shows humanized, in English).
 */
export function breadcrumbLabelKey(path: string, segment: string): string | undefined {
  const own = PATH_LABELS[path] ?? TAB_LABELS.get(path)
  if (own) return own.key
  const fromSidebar = SIDEBAR_LABELS.get(path)
  if (fromSidebar && !GENERIC_TITLES.has(fromSidebar)) return SIDEBAR_KEYS.get(path)
  return FALLBACK_LABELS[segment] ? `nav.crumb.${segment}` : undefined
}

/**
 * What a record id under each parent segment is ("/scans/<id>" is a scan):
 * the crumb for an id until its page names the record. Never the id itself.
 */
const RECORD_LABELS: Record<string, string> = {
  assets: 'Asset',
  campaigns: 'Campaign',
  cycles: 'Cycle',
  findings: 'Finding',
  groups: 'Asset group',
  organizations: 'Organization',
  remediation: 'Campaign',
  repositories: 'Repository',
  runs: 'Run',
  scans: 'Scan',
  templates: 'Template',
  workflows: 'Workflow',
}

/** Label for an id segment whose parent segment is `parent`. */
export function recordLabel(parent: string | undefined): string {
  return (parent && RECORD_LABELS[parent]) || 'Details'
}

/** The i18n key for recordLabel: `nav.record.<parent>`, or `nav.record.details`. */
export function recordLabelKey(parent: string | undefined): string {
  return parent && RECORD_LABELS[parent] ? `nav.record.${parent}` : 'nav.record.details'
}

/** Every key breadcrumbLabelKey/recordLabelKey can return besides sidebar keys (for the dictionary test). */
export const BREADCRUMB_OWN_KEYS: Record<string, string> = {
  ...Object.fromEntries(
    Object.entries({ ...FALLBACK_LABELS }).map(([seg, label]) => [`nav.crumb.${seg}`, label])
  ),
  ...Object.fromEntries(
    Object.values(PATH_LABELS)
      .filter(({ key }) => key.startsWith('nav.crumb.'))
      .map(({ key, label }) => [key, label])
  ),
  ...Object.fromEntries(
    Object.entries(RECORD_LABELS).map(([parent, label]) => [`nav.record.${parent}`, label])
  ),
  'nav.record.details': 'Details',
}
