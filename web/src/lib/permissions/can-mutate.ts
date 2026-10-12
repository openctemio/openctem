/**
 * Mutating controls (Save, Delete, Add, Test, Sync) are shown from the API's
 * own route gates, not from a permission each button picks by hand.
 *
 * `src/config/api-route-permissions.json` is generated from the API route
 * table by `api/tests/unit/route_permission_map_test.go` (CI fails when it is
 * stale). Each entry is "METHOD /path" -> the permissions the route requires,
 * "any of" groups, and the lowest tenant role it admits. This is UX only: the
 * API stays the authority.
 */
import { useMemo } from 'react'
import routePermissions from '@/config/api-route-permissions.json'
import { isRoleAtLeast, type RoleString } from './constants'
import { usePermissions } from './hooks'

export interface RouteGate {
  permissions?: string[]
  any_of?: string[][]
  min_role?: string
}

const ROUTE_GATES = routePermissions as Record<string, RouteGate>

/** A mutating API route, as written in the API route table. */
export type ApiRouteKey = keyof typeof routePermissions

export function routeGate(key: ApiRouteKey): RouteGate {
  return ROUTE_GATES[key] ?? {}
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

/** True when the current user may call every listed mutating route. */
export function useCanMutate(...keys: ApiRouteKey[]): boolean {
  const { permissions, tenantRole } = usePermissions()
  const joined = keys.join('|')
  return useMemo(
    () =>
      joined
        .split('|')
        .every((k) => passesRouteGate(routeGate(k as ApiRouteKey), permissions, tenantRole)),
    [joined, permissions, tenantRole]
  )
}
