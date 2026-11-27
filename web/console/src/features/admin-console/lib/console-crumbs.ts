import type { CrumbTrail } from '@/components/layout/breadcrumb-nav'
import type { AdminNavItem, AdminNavSection } from '../config/admin-nav'
import { activeNavUrl } from './admin-nav-visibility'

/**
 * The console's breadcrumb, from its own navigation (shell package 0.4: the
 * home icon is the console overview, no "Console" level after it). A page
 * listed in the navigation is one level, named as in the sidebar; a record
 * under it (an organization, a user) adds its kind as the current level, with
 * the list page as a link. The overview, and a page the navigation does not
 * list, show no trail.
 */
export function consoleCrumbLevels(
  pathname: string,
  sections: AdminNavSection[],
  label: (item: AdminNavItem) => string,
  recordLabel: (listUrl: string) => string
): CrumbTrail['levels'] {
  const url = activeNavUrl(pathname, sections)
  if (!url || url === '/') return []
  const item = sections.flatMap((s) => s.items).find((i) => i.url === url)
  if (!item) return []
  const levels = [{ path: url, label: label(item), hasPage: true }]
  if (pathname !== url) levels.push({ path: pathname, label: recordLabel(url), hasPage: true })
  return levels
}
