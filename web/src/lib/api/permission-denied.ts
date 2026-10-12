/**
 * "Why can't I do this?": a 403 from a permission or team-role gate names
 * what was missing in `details` (api middleware/permission_denied.go):
 * `missing_permissions` (all needed), `any_of` (one needed) or
 * `required_role`. This turns that into a sentence the person can forward to
 * an administrator. A data-scope refusal never arrives here (it is a 404),
 * and a disabled module has its own code (MODULE_NOT_ENABLED).
 */
import { getPermissionLabel } from '@/lib/permissions/constants'

export interface PermissionDeniedDetails {
  missing_permissions?: string[]
  any_of?: string[]
  required_role?: string
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : []
}

function named(permission: string): string {
  return `${getPermissionLabel(permission)} (${permission})`
}

const ROLE_SENTENCE: Record<string, string> = {
  owner: 'Only the organization owner can do this.',
  admin: 'Only an organization administrator can do this.',
  member: 'This needs the member role or higher.',
}

/**
 * The explanation for a refused action, or null when the details name
 * nothing (an older API, or another kind of 403).
 */
export function describePermissionDenied(details: unknown): string | null {
  if (!details || typeof details !== 'object') return null
  const d = details as Record<string, unknown>
  const missing = strings(d.missing_permissions)
  const anyOf = strings(d.any_of)
  const role = typeof d.required_role === 'string' ? d.required_role : ''

  if (missing.length > 0) {
    const noun = missing.length === 1 ? 'permission' : 'permissions'
    return `You need the ${noun} ${missing.map(named).join(', ')}. Ask an organization administrator to grant it through one of your roles.`
  }
  if (anyOf.length > 0) {
    return `You need one of these permissions: ${anyOf.map(named).join(', ')}. Ask an organization administrator to grant one through your roles.`
  }
  if (role) {
    return ROLE_SENTENCE[role] ?? `This needs the ${role} role.`
  }
  return null
}
