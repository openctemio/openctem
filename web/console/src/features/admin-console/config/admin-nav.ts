import {
  ArrowUpCircle,
  Bot,
  Building2,
  Activity,
  Fingerprint,
  Gauge,
  History,
  Inbox,
  MonitorSmartphone,
  KeyRound,
  LayoutDashboard,
  Library,
  LifeBuoy,
  Mail,
  Megaphone,
  Radar,
  Scale,
  Package,
  ShieldCheck,
  Cloud,
  SlidersHorizontal,
  UserCheck,
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
  /**
   * Reached from elsewhere in the shell (the personal security keys sit with
   * the signed-in administrator in the sidebar footer): left out of the
   * sidebar sections but kept in the command palette.
   */
  hideInSidebar?: boolean
}

export interface AdminNavSection {
  /** Section label; omitted for the top group. */
  title?: string
  i18nKey?: string
  items: AdminNavItem[]
}

/**
 * Console navigation (RFC-022 revision 22): Overview, then six groups by
 * what an operator is doing: Customers (organizations and people), Scanning
 * (what the platform may scan and with what), Security (who administers the
 * console and what they did), Settings (instance-wide behaviour), Monitoring
 * (is the installation healthy and current). Only pages that exist are
 * listed: add an item together with its page, never ahead of it. The command
 * palette indexes the same list.
 */
export const adminNav: AdminNavSection[] = [
  {
    items: [
      {
        title: 'Overview',
        i18nKey: 'admin.nav.overview',
        url: '/',
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
        url: '/organizations',
        icon: Building2,
        keywords: ['tenants', 'teams', 'customers'],
      },
      {
        title: 'Users',
        i18nKey: 'admin.nav.users',
        url: '/users',
        icon: UserSearch,
        // Finding people by email is personal data: not for read-only.
        minRole: 'ops_admin',
        keywords: ['accounts', 'people', 'locked', 'sessions', 'support'],
      },
      {
        title: 'Access requests',
        i18nKey: 'admin.nav.access-requests',
        url: '/requests',
        icon: Inbox,
        keywords: ['requests', 'sign-up', 'approve', 'inbox', 'pending'],
      },
      {
        title: 'Sign-ups',
        i18nKey: 'admin.nav.signups',
        url: '/requests/sign-ups',
        icon: UserPlus,
        keywords: ['sign-up', 'signups', 'registrations', 'burst', 'abuse', 'alerts'],
      },
      {
        title: 'Support access',
        i18nKey: 'admin.nav.supportAccess',
        url: '/support',
        icon: LifeBuoy,
        minRole: 'ops_admin',
        keywords: ['support', 'grant', 'case', 'help', 'troubleshoot', 'read-only'],
      },
    ],
  },
  {
    title: 'Scanning',
    i18nKey: 'admin.nav.group.scanning',
    items: [
      {
        title: 'Scan approval',
        i18nKey: 'admin.nav.scanApproval',
        url: '/system/scan-approval',
        icon: ShieldCheck,
        keywords: ['scan', 'approval', 'governance', 'second approver', 'policy', 'scope'],
      },
      {
        title: 'Platform scanning',
        i18nKey: 'admin.nav.platformScanning',
        url: '/scanning/platform',
        icon: Cloud,
        keywords: [
          'platform sensors',
          'verified domain',
          'proof',
          'ownership',
          'abuse',
          'scope',
          'shared sensors',
          'fleet',
          'pause',
          'retire',
          'queue',
          'jobs',
          'regions',
          'egress',
          'zones',
          'anomaly',
        ],
      },
      {
        title: 'Target mappings',
        i18nKey: 'admin.nav.targetMappings',
        url: '/scanning/target-mappings',
        icon: Waypoints,
        keywords: ['asset types', 'scanner'],
      },
      {
        title: 'Content packs',
        i18nKey: 'admin.nav.contentPacks',
        url: '/system/content-packs',
        icon: Package,
        keywords: ['templates', 'nuclei', 'semgrep', 'wordlists', 'channels', 'signing'],
      },
      {
        title: 'Content catalog',
        i18nKey: 'admin.nav.contentCatalog',
        url: '/scanning/content-catalog',
        icon: Library,
        keywords: [
          'catalog',
          'packages',
          'bundle',
          'import',
          'revoke',
          'rules',
          'sensors',
          'signed',
        ],
      },
      {
        title: 'Threat intelligence',
        i18nKey: 'admin.nav.threatIntel',
        url: '/system/threat-intel',
        icon: Radar,
        keywords: ['epss', 'kev', 'feeds', 'sync'],
      },
    ],
  },
  {
    title: 'Security',
    i18nKey: 'admin.nav.group.security',
    items: [
      {
        title: 'Administrators',
        i18nKey: 'admin.nav.administrators',
        url: '/security/administrators',
        icon: UserCog,
        minRole: 'super_admin',
        keywords: ['admins', 'break-glass', 'roster'],
      },
      {
        title: 'Sessions',
        i18nKey: 'admin.nav.sessions',
        url: '/security/sessions',
        icon: MonitorSmartphone,
        minRole: 'super_admin',
        keywords: ['signed in', 'console sessions', 'sign out', 'devices'],
      },
      {
        title: 'Approvals',
        i18nKey: 'admin.nav.approvals',
        url: '/security/approvals',
        icon: UserCheck,
        minRole: 'super_admin',
        keywords: ['four-eyes', 'second approval', 'approve', 'dual control'],
      },
      {
        title: 'Admin sign-in',
        i18nKey: 'admin.nav.adminSignIn',
        url: '/system/admin-sign-in',
        icon: KeyRound,
        minRole: 'super_admin',
        keywords: ['identity provider', 'idp', 'sso', 'oidc'],
      },
      {
        title: 'Admin activity',
        i18nKey: 'admin.nav.activity',
        url: '/security/activity',
        icon: History,
        keywords: ['audit', 'logs', 'system logs', 'history'],
      },
      {
        title: 'My security keys',
        i18nKey: 'admin.nav.securityKeys',
        url: '/security/keys',
        icon: Fingerprint,
        hideInSidebar: true,
        keywords: ['passkey', 'webauthn', 'fido2', 'two-factor', 'recovery codes', 'mfa'],
      },
    ],
  },
  {
    title: 'Settings',
    i18nKey: 'admin.nav.group.settings',
    items: [
      {
        title: 'Configuration',
        i18nKey: 'admin.nav.configuration',
        url: '/system/configuration',
        icon: SlidersHorizontal,
        keywords: ['settings', 'environment', 'restart', 'secrets', 'source', 'env'],
      },
      {
        title: 'Sign-up',
        i18nKey: 'admin.nav.signUp',
        url: '/system/sign-up',
        icon: UserPlus,
        keywords: ['registration', 'self-service', 'policy'],
      },
      {
        title: 'Limits',
        i18nKey: 'admin.nav.limits',
        url: '/system/limits',
        icon: Gauge,
        keywords: ['limits', 'quotas', 'self-service', 'seats'],
      },
      {
        title: 'E-mail',
        i18nKey: 'admin.nav.email',
        url: '/system/email',
        icon: Mail,
        keywords: ['smtp', 'mail', 'invitations', 'notifications', 'sender'],
      },
      {
        title: 'Legal',
        i18nKey: 'admin.nav.legal',
        url: '/system/legal',
        icon: Scale,
        keywords: ['terms', 'privacy', 'security.txt', 'contact', 'policy'],
      },
      {
        title: 'Announcements',
        i18nKey: 'admin.nav.announcements',
        url: '/system/announcements',
        icon: Megaphone,
        keywords: ['maintenance', 'banner', 'notice', 'downtime'],
      },
      {
        title: 'AI applications',
        i18nKey: 'admin.nav.aiApplications',
        url: '/system/ai-applications',
        icon: Bot,
        keywords: ['mcp', 'oauth', 'clients', 'connected apps'],
      },
    ],
  },
  {
    title: 'Monitoring',
    i18nKey: 'admin.nav.group.monitoring',
    items: [
      {
        title: 'Health',
        i18nKey: 'admin.nav.health',
        url: '/health',
        icon: Activity,
        keywords: [
          'status',
          'database',
          'redis',
          'queues',
          'version',
          'migrations',
          'jobs',
          'system',
          'operations',
          'disk',
          'storage',
          'backup',
          'certificate',
          'expiry',
          'free space',
        ],
      },
      {
        title: 'Software updates',
        i18nKey: 'admin.nav.softwareUpdates',
        url: '/system/software-updates',
        icon: ArrowUpCircle,
        keywords: ['version', 'upgrade', 'release', 'security advisory', 'update check'],
      },
    ],
  },
]
