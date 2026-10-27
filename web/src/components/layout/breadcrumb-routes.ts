/**
 * Which breadcrumb parents can be links.
 *
 * The trail is built from the URL, so every parent segment used to become a
 * link. Some parents are only folders in `src/app` with no page of their own
 * (`/insights`, `/pentest`, `/settings/access-control`, ...): their crumb led
 * to the 404 page, and Next.js prefetched each of them (a 404 in the network
 * log on every page under them). Those parents render as plain text instead.
 *
 * PATHS_WITHOUT_PAGE lists them; `__tests__/breadcrumb-routes.test.ts` rebuilds
 * the list from `src/app` and fails when a page is added or removed without
 * updating it.
 */

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** True for a segment that is a record id (UUID, ObjectId, a long number or a vulnerability id). */
export function isIdSegment(segment: string): boolean {
  if (UUID_PATTERN.test(segment)) return true
  if (/^[0-9a-f]{24}$/i.test(segment)) return true // MongoDB ObjectId
  if (/^[0-9]+$/.test(segment) && segment.length > 5) return true // Long numeric IDs
  // A vulnerability id (/vulnerabilities/CVE-2024-3094, or an advisory id).
  if (/^CVE-\d{4}-\d{4,19}$/i.test(segment)) return true
  if (/^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/i.test(segment)) return true
  return false
}

/**
 * Parent paths in `src/app` that have no page.tsx (route groups removed, any
 * dynamic segment written as `[id]`).
 */
export const PATHS_WITHOUT_PAGE: ReadonlySet<string> = new Set([
  '/auth',
  '/auth/callback',
  '/auth/sso',
  '/auth/sso/callback',
  '/ci-cd/github-app',
  '/insights',
  '/mcp',
  '/mcp/confirm',
  '/oauth',
  '/onboarding',
  '/pentest',
  '/pentest/findings',
  '/pentest/findings/[id]',
  '/settings/tenant',
  '/settings/pentest/templates/[id]',
  '/settings/scanning',
])

/** Whether `path` (a real URL path, ids included) has a page to link to. */
export function breadcrumbHasPage(path: string): boolean {
  const pattern = path
    .split('/')
    .map((s) => (isIdSegment(s) ? '[id]' : s))
    .join('/')
  return !PATHS_WITHOUT_PAGE.has(pattern)
}
