/**
 * Where the console goes after the organization changes.
 *
 * The address of the previous organization may name its records (a finding
 * id in the path) or its list state (page, filters, a selected row, an open
 * panel in the query). Neither means anything in the new organization, and
 * keeping them would send the old organization's ids to the new session. The
 * landing is the same section's list root without any query: the longest
 * prefix of the path that is a page of its own and stops before the first
 * dynamic segment (`/findings/<id>` -> `/findings`, `/scans/<id>` ->
 * `/scans`, `/findings?page=5` -> `/findings`), else the dashboard.
 *
 * DYNAMIC_PAGE_ROUTES lists every page route with a dynamic segment;
 * `__tests__/org-switch-landing.test.ts` rebuilds the list from `src/app` and
 * fails when a page is added without it.
 * Rule: web/docs/organization-switch.md.
 */

import { PATHS_WITHOUT_PAGE, isIdSegment } from '@/components/layout/breadcrumb-routes'

/** Page routes in src/app with a dynamic segment (route groups removed, `[x]` written as `[id]`). */
export const DYNAMIC_PAGE_ROUTES: readonly string[] = [
  '/assets/[id]',
  '/assets/groups/[id]',
  '/components/[id]',
  '/cycles/[id]',
  '/emerging-threats/[id]',
  '/findings/[id]',
  '/invitations/[id]',
  '/mcp/confirm/[id]',
  '/pentest/campaigns/[id]',
  '/pentest/findings/[id]/edit',
  '/programs/[id]',
  '/remediation/campaigns/[id]',
  '/remediation/tasks/[id]',
  '/scans/[id]',
  '/scans/workflows/[id]',
  '/settings/integrations/import-mappings/[id]',
  '/settings/integrations/ticketing/mappings/[id]',
  '/settings/pentest/templates/[id]/edit',
  '/vulnerabilities/[id]',
]

/**
 * Static pages beside a dynamic segment: Next.js serves `/assets/groups` from
 * its own page, not from `/assets/[id]`, so these names are never ids.
 */
export const STATIC_BESIDE_DYNAMIC: Readonly<Record<string, readonly string[]>> = {
  '/assets': ['attention', 'changes', 'duplicates', 'groups', 'suggestions'],
  '/findings': ['approvals', 'imports', 'ready-to-close', 'triage'],
  '/pentest/findings': ['new'],
  '/programs': ['new'],
  '/scans': ['approvals', 'runs', 'workflows'],
  '/settings/integrations/import-mappings': ['new'],
  '/settings/pentest/templates': ['new'],
}

const DYNAMIC_PATTERNS = DYNAMIC_PAGE_ROUTES.map((r) => r.split('/').filter(Boolean))

function isStaticBeside(segments: string[], i: number): boolean {
  const parent = '/' + segments.slice(0, i).join('/')
  return STATIC_BESIDE_DYNAMIC[parent]?.includes(segments[i]) ?? false
}

/** Index of the first segment of `segments` that a dynamic route fills, or -1. */
function firstDynamicIndex(segments: string[]): number {
  let first = -1
  for (const pattern of DYNAMIC_PATTERNS) {
    if (pattern.length !== segments.length) continue
    let at = -1
    let matches = true
    for (let i = 0; i < pattern.length; i++) {
      if (pattern[i] === '[id]') {
        if (isStaticBeside(segments, i)) {
          matches = false
          break
        }
        if (at < 0) at = i
      } else if (pattern[i] !== segments[i]) {
        matches = false
        break
      }
    }
    if (matches && at >= 0 && (first < 0 || at < first)) first = at
  }
  return first
}

/** The page to open after switching organization while on `pathname`. */
export function orgSwitchLanding(pathname: string): string {
  const path = (pathname || '/').split(/[?#]/)[0]
  const segments = path.split('/').filter(Boolean)
  let cut = firstDynamicIndex(segments)
  if (cut < 0) cut = segments.length
  // An id in a path no route lists (an unknown page) still never survives.
  const idAt = segments.findIndex(isIdSegment)
  if (idAt >= 0 && idAt < cut) cut = idAt
  const kept = segments.slice(0, cut)
  while (kept.length > 0 && PATHS_WITHOUT_PAGE.has('/' + kept.join('/'))) kept.pop()
  return '/' + kept.join('/')
}

/**
 * True when the address carries nothing of an organization: no query and a
 * path that is already its own landing. Such an address may stay as it is
 * across a switch.
 */
export function isOrgNeutralAddress(pathname: string, search: string): boolean {
  const s = search.startsWith('?') ? search.slice(1) : search
  return s === '' && orgSwitchLanding(pathname) === (pathname || '/')
}
