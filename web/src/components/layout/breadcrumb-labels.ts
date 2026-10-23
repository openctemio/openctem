import { sidebarData } from '@/config/sidebar-data'
import { settingsNavItems } from '@/config/settings-nav'

/**
 * Breadcrumb labels come from the navs (main sidebar and settings rail), the
 * places pages are named, so the trail always says what the menu says. Only paths the sidebar does not
 * list fall back to FALLBACK_LABELS, then to the segment itself.
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
  return map
})()

/** Sub-pages the sidebar does not list, by full path. */
const PATH_LABELS: Record<string, string> = {
  // The first tab of Scoping > Business context: the row is named after the
  // section, the crumb after the page (its siblings humanize to "Business
  // services" and "Business units").
  '/crown-jewels': 'Crown jewels',
  // Attack surface > Suggestions (the decisions that still need a person).
  '/attack-surface/review': 'Suggestions',
}

/** Segments that are not sidebar entries themselves (section roots, sub-pages). */
const FALLBACK_LABELS: Record<string, string> = {
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

/**
 * Menu titles that only make sense inside their menu group ("Overview"), or
 * that name a section's index page ("All integrations", "Profile" for
 * /account): as a crumb, the section's own name reads better.
 */
const GENERIC_TITLES = new Set(['Overview', 'All', 'All integrations', 'Profile'])

/** Label for the breadcrumb item at `path` whose last segment is `segment`. */
export function breadcrumbLabel(path: string, segment: string): string {
  if (PATH_LABELS[path]) return PATH_LABELS[path]
  const fromSidebar = SIDEBAR_LABELS.get(path)
  if (fromSidebar && !GENERIC_TITLES.has(fromSidebar)) return fromSidebar
  return FALLBACK_LABELS[segment] ?? humanize(segment)
}

/**
 * The i18n key for the same label, so the trail speaks the reader's language:
 * the key the sidebar or settings rail renders the page with, else
 * `nav.crumb.<segment>` for the section names above. Undefined for a segment
 * with no known name (it shows humanized, in English).
 */
export function breadcrumbLabelKey(path: string, segment: string): string | undefined {
  if (PATH_LABELS[path]) return `nav.crumb.${segment}`
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
    Object.entries(PATH_LABELS).map(([path, label]) => [
      `nav.crumb.${path.split('/').pop()}`,
      label,
    ])
  ),
  ...Object.fromEntries(
    Object.entries(RECORD_LABELS).map(([parent, label]) => [`nav.record.${parent}`, label])
  ),
  'nav.record.details': 'Details',
}
