import { sidebarData } from '@/config/sidebar-data'
import { settingsNavItems } from '@/config/settings-nav'

/**
 * Breadcrumb labels come from the navs (main sidebar and settings rail), the
 * places pages are named, so the trail always says what the menu says. Only paths the sidebar does not
 * list fall back to FALLBACK_LABELS, then to the segment itself.
 */

type NavNode = { title?: string; url?: string; items?: NavNode[] }

function collect(nodes: NavNode[] | undefined, into: Map<string, string>) {
  for (const n of nodes ?? []) {
    if (n.url && n.title && !into.has(n.url)) into.set(n.url, n.title)
    collect(n.items, into)
  }
}

const SIDEBAR_LABELS: Map<string, string> = (() => {
  const map = new Map<string, string>()
  for (const group of sidebarData.navGroups as NavNode[]) collect(group.items, map)
  // Settings pages live in the settings rail, not the main sidebar.
  collect(settingsNavItems, map)
  return map
})()

/** Sub-pages the sidebar does not list, by full path. */
const PATH_LABELS: Record<string, string> = {
  // The first tab of Scoping > Business context: the row is named after the
  // section, the crumb after the page (its siblings humanize to "Business
  // services" and "Business units").
  '/crown-jewels': 'Crown jewels',
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
