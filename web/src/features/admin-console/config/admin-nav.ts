import {
  Building2,
  Inbox,
  KeyRound,
  LayoutDashboard,
  ScrollText,
  UserCog,
  UserPlus,
  Waypoints,
  type LucideIcon,
} from 'lucide-react'
import type { AdminRole } from '../types'

export interface AdminNavItem {
  title: string
  url: string
  icon: LucideIcon
  /** Minimum admin role to see the item; omitted = any admin. */
  minRole?: AdminRole
}

export interface AdminNavSection {
  /** Section label; omitted for the top group. */
  title?: string
  items: AdminNavItem[]
}

/**
 * Console navigation (Organizations, Users, Scanning, System). Only pages that exist are listed. Add an
 * item together with its page, never ahead of it.
 */
export const adminNav: AdminNavSection[] = [
  {
    items: [{ title: 'Overview', url: '/admin', icon: LayoutDashboard }],
  },
  {
    title: 'Manage',
    items: [
      { title: 'Organizations', url: '/admin/organizations', icon: Building2 },
      { title: 'Access requests', url: '/admin/organizations/access-requests', icon: Inbox },
      {
        title: 'Administrators',
        url: '/admin/administrators',
        icon: UserCog,
        minRole: 'super_admin',
      },
    ],
  },
  {
    title: 'Scanning',
    items: [{ title: 'Target mappings', url: '/admin/scanning/target-mappings', icon: Waypoints }],
  },
  {
    title: 'System',
    items: [
      {
        title: 'Admin sign-in',
        url: '/admin/system/admin-sign-in',
        icon: KeyRound,
        minRole: 'super_admin',
      },
      { title: 'Sign-up', url: '/admin/system/sign-up', icon: UserPlus },
      { title: 'System logs', url: '/admin/system-logs', icon: ScrollText },
    ],
  },
]
