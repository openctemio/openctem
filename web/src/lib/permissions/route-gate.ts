/**
 * The check behind mutating-control gates, apart from the generated route
 * table (`can-mutate.ts`) so a caller that needs one known gate does not carry
 * the whole table.
 */
import { isRoleAtLeast, type RoleString } from './constants'

export interface RouteGate {
  permissions?: string[]
  any_of?: string[][]
  min_role?: string
}

/**
 * Whether a caller with these permissions and tenant role passes the route's
 * gate. An unknown role never passes a role gate.
 */
export function passesRouteGate(
  gate: RouteGate,
  permissions: readonly string[],
  role: string | undefined
): boolean {
  if (gate.min_role) {
    if (!role || !isRoleAtLeast(role, gate.min_role as RoleString)) return false
  }
  for (const p of gate.permissions ?? []) {
    if (!permissions.includes(p)) return false
  }
  for (const group of gate.any_of ?? []) {
    if (!group.some((p) => permissions.includes(p))) return false
  }
  return true
}
