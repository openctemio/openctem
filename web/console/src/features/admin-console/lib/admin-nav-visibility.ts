import { adminNav, type AdminNavSection } from '../config/admin-nav'
import { adminMayHave, type AdminIdentity } from '../types'

/**
 * The console navigation an administrator sees: items whose permission the
 * administrator's platform roles grant (elevated or not: the page then offers
 * the elevation), and no section left empty. The sidebar and the command
 * palette both read it, so they never disagree. Hiding is a convenience; the
 * API refuses the routes behind them on its own.
 */
export function visibleAdminNav(admin: AdminIdentity): AdminNavSection[] {
  return adminNav
    .map((section) => ({
      ...section,
      items: section.items.filter(
        (item) => !item.permission || adminMayHave(admin, item.permission)
      ),
    }))
    .filter((section) => section.items.length > 0)
}

function ownsPath(pathname: string, url: string): boolean {
  if (url === '/') return pathname === '/'
  return pathname === url || pathname.startsWith(`${url}/`)
}

/**
 * The url of the entry that owns the current page: the deepest matching one,
 * so /requests/sign-ups marks Sign-ups and not Access requests.
 */
export function activeNavUrl(pathname: string, sections: AdminNavSection[]): string | undefined {
  return sections
    .flatMap((s) => s.items.map((i) => i.url))
    .filter((url) => ownsPath(pathname, url))
    .sort((x, y) => y.length - x.length)[0]
}

/** The sections of the main sidebar (everything but the settings rail). */
export function mainNavSections(sections: AdminNavSection[]): AdminNavSection[] {
  return sections.filter((s) => !s.rail)
}

/** The sections of the settings rail. */
export function settingsRailSections(sections: AdminNavSection[]): AdminNavSection[] {
  return sections.filter((s) => s.rail === 'settings')
}

/** Whether the current page is one of the settings rail's pages. */
export function isSettingsRailPath(pathname: string, sections: AdminNavSection[]): boolean {
  const url = activeNavUrl(pathname, sections)
  return !!url && settingsRailSections(sections).some((s) => s.items.some((i) => i.url === url))
}
