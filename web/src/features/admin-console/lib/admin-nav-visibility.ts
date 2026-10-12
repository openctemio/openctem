import { adminNav, type AdminNavSection } from '../config/admin-nav'
import { adminCan, type AdminRole } from '../types'

/**
 * The console navigation an administrator of this role sees: items above the
 * role are left out, and so is a section left empty. The sidebar and the
 * command palette both read it, so they never disagree. Hiding is a
 * convenience; the API refuses the routes behind them on its own.
 */
export function visibleAdminNav(role: AdminRole): AdminNavSection[] {
  return adminNav
    .map((section) => ({
      ...section,
      items: section.items.filter((item) => !item.minRole || adminCan(role, item.minRole)),
    }))
    .filter((section) => section.items.length > 0)
}
