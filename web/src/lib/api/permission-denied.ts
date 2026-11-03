/**
 * "Why can't I do this, and who can?": a 403 from a permission or team-role
 * gate names what was missing in `details` (api middleware/permission_denied.go):
 * `missing_permissions` (all needed), `any_of` (one needed) or
 * `required_role`. This turns that into a sentence the person can forward to
 * an administrator: the permission by its id, the built-in roles that hold
 * it, and who can grant it. A data-scope refusal never arrives here (it is a
 * 404), and a disabled module has its own code (MODULE_NOT_ENABLED).
 *
 * Every sentence comes from the catalog (common.access.*); callers outside
 * React get the page's language.
 */
import { getDictionary, translate, type TranslateVars } from '@/lib/i18n'
import { heldByKey, rolesGrantingAll } from '@/lib/permissions/who-can'

export interface PermissionDeniedDetails {
  missing_permissions?: string[]
  any_of?: string[]
  required_role?: string
}

export type Translate = (key: string, fallback?: string, vars?: TranslateVars) => string

/** Translator for code with no React context: the page's language. */
function pageTranslate(): Translate {
  const lang = typeof document !== 'undefined' ? document.documentElement.lang : undefined
  const dict = getDictionary(lang || undefined)
  return (key, fallback, vars) => translate(dict, key, fallback, vars)
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : []
}

const HELD_BY_FALLBACK: Record<string, string> = {
  'common.access.heldBy.owner': 'Only the owner has it among the built-in roles.',
  'common.access.heldBy.owner-admin': 'Owners and administrators have it.',
  'common.access.heldBy.owner-admin-member': 'Owners, administrators and members have it.',
  'common.access.heldBy.all': 'Every built-in role has it.',
  'common.access.heldBy.none': 'No built-in role has it; a custom role can grant it.',
}

/** "Owners and administrators have it." for the permissions of a refusal. */
export function describeHolders(permissions: string[], anyOf: boolean, t: Translate): string {
  const key = heldByKey(rolesGrantingAll(permissions, anyOf))
  return t(key, HELD_BY_FALLBACK[key] ?? HELD_BY_FALLBACK['common.access.heldBy.none'])
}

/**
 * The explanation for a refused action, or null when the details name
 * nothing (an older API, or another kind of 403).
 */
export function describePermissionDenied(
  details: unknown,
  t: Translate = pageTranslate()
): string | null {
  if (!details || typeof details !== 'object') return null
  const d = details as Record<string, unknown>
  const missing = strings(d.missing_permissions)
  const anyOf = strings(d.any_of)
  const role = typeof d.required_role === 'string' ? d.required_role : ''
  const ask = t(
    'common.access.askGrant',
    'Ask an owner or administrator to give it to you through a role.'
  )

  if (missing.length > 0) {
    const list = missing.join(', ')
    const need =
      missing.length === 1
        ? t('common.access.needPermission', 'You need the permission {list}.', { list })
        : t('common.access.needPermissions', 'You need the permissions {list}.', { list })
    return `${need} ${describeHolders(missing, false, t)} ${ask}`
  }
  if (anyOf.length > 0) {
    const need = t('common.access.needAnyOf', 'You need one of these permissions: {list}.', {
      list: anyOf.join(', '),
    })
    return `${need} ${describeHolders(anyOf, true, t)} ${ask}`
  }
  if (role === 'owner') {
    return t('common.access.roleOwner', 'Only the organization owner can do this.')
  }
  if (role === 'admin') {
    return t(
      'common.access.roleAdmin',
      'Only an owner or administrator of the organization can do this.'
    )
  }
  if (role === 'member') {
    return t('common.access.roleMember', 'This needs the member role or higher.')
  }
  if (role) {
    return t('common.access.roleOther', 'This needs the {role} role.', { role })
  }
  return null
}
