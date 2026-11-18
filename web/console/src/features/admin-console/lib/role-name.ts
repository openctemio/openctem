import { useTranslation } from '@/context/i18n-provider'
import { humanizeIdentifier } from '@/lib/humanize-identifier'

/**
 * The one name of a platform role in the console: the shell, Roles,
 * Administrators, Sessions, the create-administrator dialog, the elevation
 * list, row menus and toasts all read it from here. The API still sends the
 * base tier (super_admin, ops_admin, readonly) on administrators and sessions;
 * a tier shows under the platform role it stands for.
 */
const PLATFORM_ROLE_OF_TIER: Record<string, string> = {
  super_admin: 'platform_owner',
  ops_admin: 'platform_admin',
  readonly: 'platform_viewer',
}

const ENGLISH: Record<string, string> = {
  platform_owner: 'Platform owner',
  platform_admin: 'Platform admin',
  platform_viewer: 'Read-only',
  operator: 'Operator',
  support: 'Support',
  security_auditor: 'Security auditor',
  billing: 'Billing',
}

type Translate = ReturnType<typeof useTranslation>['t']

/** The platform role key a role value stands for (a tier maps to its role). */
export function platformRoleKey(role: string): string {
  return PLATFORM_ROLE_OF_TIER[role] ?? role
}

/** The dictionary key and English name of a role value. */
export function roleNameParts(role: string): { key: string; fallback: string } {
  const k = platformRoleKey(role)
  return { key: `admin.platformRole.${k}`, fallback: ENGLISH[k] ?? humanizeIdentifier(k) }
}

/** The role's name in the console language. */
export function roleName(t: Translate, role: string): string {
  const { key, fallback } = roleNameParts(role)
  return t(key, fallback)
}

/** `roleName` bound to the active language. */
export function useRoleName(): (role: string) => string {
  const { t } = useTranslation()
  return (role) => roleName(t, role)
}
