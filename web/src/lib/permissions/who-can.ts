/**
 * "Who can do this?": the built-in organization roles that hold a permission,
 * from the client mirror of the API's role mapping (RolePermissions, kept in
 * step with api/pkg/domain/permission/role_mapping.go). A custom role can
 * grant any permission too, so a sentence built from this always ends with
 * "ask an owner or administrator", never "nobody can".
 *
 * Display only: the API decides every request.
 */
import { Role, RolePermissions, type RoleString } from './constants'

/** Most to least privileged, the order the roles are named in. */
const ORDER: RoleString[] = [Role.Owner, Role.Admin, Role.Member, Role.Viewer]

/** Built-in roles that hold `permission`, owner first. */
export function rolesGranting(permission: string): RoleString[] {
  return ORDER.filter((role) => (RolePermissions[role] as readonly string[]).includes(permission))
}

/**
 * Built-in roles that hold every one of `permissions` (all needed) or, with
 * `anyOf`, at least one of them.
 */
export function rolesGrantingAll(permissions: string[], anyOf = false): RoleString[] {
  if (permissions.length === 0) return []
  return ORDER.filter((role) => {
    const held = RolePermissions[role] as readonly string[]
    return anyOf
      ? permissions.some((p) => held.includes(p))
      : permissions.every((p) => held.includes(p))
  })
}

/**
 * The i18n key of the sentence naming who holds a permission among the
 * built-in roles: `common.access.heldBy.<roles joined by "-">`, one key per
 * combination that occurs (owner; owner-admin; owner-admin-member; all), or
 * `none` when only a custom role can grant it.
 */
export function heldByKey(roles: RoleString[]): string {
  if (roles.length === 0) return 'common.access.heldBy.none'
  if (roles.length === ORDER.length) return 'common.access.heldBy.all'
  return `common.access.heldBy.${roles.join('-')}`
}
