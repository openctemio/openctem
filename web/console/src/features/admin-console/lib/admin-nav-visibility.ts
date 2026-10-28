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
