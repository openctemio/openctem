import {
  Bot,
  Building2,
  Activity,
  Gauge,
  History,
  Inbox,
  MonitorSmartphone,
  KeyRound,
  LayoutDashboard,
  Megaphone,
  Radar,
  Package,
  ShieldCheck,
  UserCog,
  UserPlus,
  UserSearch,
  Waypoints,
  type LucideIcon,
} from 'lucide-react'
import type { AdminRole } from '../types'

export interface AdminNavItem {
  /** English label; also the i18n fallback. */
  title: string
  /** Dictionary key for the label. */
  i18nKey: string
  url: string
  icon: LucideIcon
  /** Minimum admin role to see the item; omitted = any admin. */
  minRole?: AdminRole
  /** Extra words the command palette matches (synonyms). */
  keywords?: string[]
}

export interface AdminNavSection {
  /** Section label; omitted for the top group. */
  title?: string
  i18nKey?: string
  items: AdminNavItem[]
}

/**
 * Console navigation (research/79 information architecture): Overview,
 * Organizations, Scanning, Security, System. Only pages that exist are
 * listed: add an item together with its page, never ahead of it. The command
 * palette indexes the same list.
 */
export const adminNav: AdminNavSection[] = [
  {
    items: [
      {
        title: 'Overview',
        i18nKey: 'admin.nav.overview',
        url: '/admin',
        icon: LayoutDashboard,
        keywords: ['home', 'attention', 'dashboard'],
      },
    ],
  },
  {
    title: 'Customers',
    i18nKey: 'admin.nav.group.customers',
    items: [
      {
        title: 'Organizations',
        i18nKey: 'admin.nav.organizations',
        url: '/admin/organizations',
        icon: Building2,
        keywords: ['tenants', 'teams', 'customers'],
      },
      {
        title: 'Users',
        i18nKey: 'admin.nav.users',
        url: '/admin/users',
        icon: UserSearch,
        keywords: ['accounts', 'people', 'locked', 'sessions', 'support'],
      },
    ],
  },
  {
    title: 'Requests',
    i18nKey: 'admin.nav.group.requests',
    items: [
      {
        title: 'Access requests',
        i18nKey: 'admin.nav.access-requests',
        url: '/admin/requests',
        icon: Inbox,
        keywords: ['requests', 'sign-up', 'approve', 'inbox', 'pending'],
      },
    ],
  },
  {
    title: 'Scanning',
    i18nKey: 'admin.nav.group.scanning',
    items: [
      {
        title: 'Target mappings',
        i18nKey: 'admin.nav.targetMappings',
        url: '/admin/scanning/target-mappings',
        icon: Waypoints,
        keywords: ['asset types', 'scanner'],
      },
    ],
  },
  {
    title: 'Security',
    i18nKey: 'admin.nav.group.security',
    items: [
      {
        title: 'Admin activity',
        i18nKey: 'admin.nav.activity',
        url: '/admin/security/activity',
        icon: History,
        keywords: ['audit', 'logs', 'system logs', 'history'],
      },
      {
        title: 'Sessions',
        i18nKey: 'admin.nav.sessions',
        url: '/admin/security/sessions',
        icon: MonitorSmartphone,
        minRole: 'super_admin',
        keywords: ['signed in', 'console sessions', 'sign out', 'devices'],
      },
      {
        title: 'Administrators',
        i18nKey: 'admin.nav.administrators',
        url: '/admin/security/administrators',
        icon: UserCog,
        minRole: 'super_admin',
        keywords: ['admins', 'break-glass', 'roster'],
      },
    ],
  },
  {
    title: 'System',
    i18nKey: 'admin.nav.group.system',
    items: [
      {
        title: 'Sign-up',
        i18nKey: 'admin.nav.signUp',
        url: '/admin/system/sign-up',
        icon: UserPlus,
        keywords: ['registration', 'self-service', 'policy'],
      },
      {
        title: 'Scan approval',
        i18nKey: 'admin.nav.scanApproval',
        url: '/admin/system/scan-approval',
        icon: ShieldCheck,
        keywords: ['scan', 'approval', 'governance', 'second approver', 'policy', 'scope'],
      },
      {
        title: 'Admin sign-in',
        i18nKey: 'admin.nav.adminSignIn',
        url: '/admin/system/admin-sign-in',
        icon: KeyRound,
        minRole: 'super_admin',
        keywords: ['identity provider', 'idp', 'sso', 'oidc'],
      },
      {
        title: 'Plans',
        i18nKey: 'admin.nav.plans',
        url: '/admin/system/plans',
        icon: Gauge,
        keywords: ['limits', 'free', 'pro', 'enterprise', 'quotas'],
      },
      {
        title: 'Content packs',
        i18nKey: 'admin.nav.contentPacks',
        url: '/admin/system/content-packs',
        icon: Package,
        keywords: ['templates', 'nuclei', 'semgrep', 'wordlists', 'channels', 'signing'],
      },
      {
        title: 'Threat intelligence',
        i18nKey: 'admin.nav.threatIntel',
        url: '/admin/system/threat-intel',
        icon: Radar,
        keywords: ['epss', 'kev', 'feeds', 'sync'],
      },
      {
        title: 'Announcements',
        i18nKey: 'admin.nav.announcements',
        url: '/admin/system/announcements',
        icon: Megaphone,
        keywords: ['maintenance', 'banner', 'notice', 'downtime'],
      },
      {
        title: 'AI applications',
        i18nKey: 'admin.nav.aiApplications',
        url: '/admin/system/ai-applications',
        icon: Bot,
        keywords: ['mcp', 'oauth', 'clients', 'connected apps'],
      },
    ],
  },
  {
    title: 'Operations',
    i18nKey: 'admin.nav.group.operations',
    items: [
      {
        title: 'Health',
        i18nKey: 'admin.nav.operations',
        url: '/admin/operations',
        icon: Activity,
        keywords: ['status', 'database', 'redis', 'queues', 'version', 'migrations', 'jobs'],
      },
    ],
  },
]
