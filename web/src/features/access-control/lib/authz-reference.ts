/**
 * The generated authorization reference (src/config/authz-matrix.json).
 *
 * The API generates it from its own source (`go run ./cmd/gen-authz-docs`,
 * run by `make generate`): the permission catalog, the built-in roles, the
 * role templates and, per feature, every route with the permissions it
 * requires. It is not committed. This is UX only: the API gates stay the
 * authority.
 *
 * The file is large, so it is loaded on demand (useAuthzReference), never
 * imported statically into a shared bundle.
 */
import { useEffect, useState } from 'react'

export interface AuthzGate {
  permissions?: string[]
  any_of?: string[][]
  min_role?: string
  modules?: string[]
  step_up?: boolean
  other?: string[]
}

export interface AuthzRoute {
  method: string
  path: string
  gate: AuthzGate
  data_scope: { class: string; note?: string }
  ungated?: string
}

export interface AuthzFeature {
  id: string
  title: string
  description: string
  stages?: string[]
  modules?: string[]
  permissions: string[]
  routes: AuthzRoute[]
}

export interface AuthzPermission {
  id: string
  module: string
  name: string
  description?: string
  admin_only?: boolean
}

export interface AuthzRole {
  id: string
  kind: 'system' | 'template'
  name: string
  description: string
  personas?: string[]
  has_full_data_access: boolean
  admin_bypass?: boolean
  permissions: string[]
}

export interface AuthzReference {
  version: number
  permissions: AuthzPermission[]
  roles: AuthzRole[]
  features: AuthzFeature[]
}

/** The role templates: starting points for a custom role. */
export function roleTemplates(ref: AuthzReference): AuthzRole[] {
  return ref.roles.filter((r) => r.kind === 'template')
}

/**
 * Whether a holder of these permissions passes a route's permission checks.
 * A team-role gate (admin, owner) is passed only by the system owner and
 * admin roles (adminBypass); other named gates (campaign role) are not
 * decided here.
 */
export function passesGate(gate: AuthzGate, permissions: readonly string[], adminBypass: boolean) {
  if (gate.min_role && !adminBypass) return false
  if (adminBypass) return true
  for (const p of gate.permissions ?? []) {
    if (!permissions.includes(p)) return false
  }
  for (const group of gate.any_of ?? []) {
    if (!group.some((p) => permissions.includes(p))) return false
  }
  return true
}

export interface FeatureCapability {
  feature: AuthzFeature
  /** The feature's permissions this role holds. */
  held: string[]
  /** Gated routes of the feature this role passes, and how many there are. */
  allowedRoutes: number
  gatedRoutes: number
}

/** What a role (by its permissions) can do in each feature. */
export function featureCapabilities(
  ref: AuthzReference,
  permissions: readonly string[],
  adminBypass: boolean
): FeatureCapability[] {
  return ref.features
    .filter((f) => f.permissions.length > 0)
    .map((feature) => {
      const gated = feature.routes.filter(
        (r) =>
          !r.ungated && ((r.gate.permissions?.length ?? 0) > 0 || (r.gate.any_of?.length ?? 0) > 0)
      )
      return {
        feature,
        held: adminBypass
          ? feature.permissions
          : feature.permissions.filter((p) => permissions.includes(p)),
        allowedRoutes: gated.filter((r) => passesGate(r.gate, permissions, adminBypass)).length,
        gatedRoutes: gated.length,
      }
    })
}

/** System roles whose holders pass every permission check. */
export function isAdminBypassRole(slug: string, isSystem: boolean): boolean {
  return isSystem && (slug === 'owner' || slug === 'admin')
}

/**
 * Loads the reference on demand. `reference` stays null until it has loaded,
 * and `unavailable` is true when the generated file is missing (run
 * `make generate`).
 */
export function useAuthzReference(enabled = true): {
  reference: AuthzReference | null
  unavailable: boolean
} {
  const [reference, setReference] = useState<AuthzReference | null>(null)
  const [unavailable, setUnavailable] = useState(false)
  useEffect(() => {
    if (!enabled || reference) return
    let cancelled = false
    import('@/config/authz-matrix.json')
      .then((m) => {
        if (!cancelled) setReference((m.default ?? m) as unknown as AuthzReference)
      })
      .catch(() => {
        if (!cancelled) setUnavailable(true)
      })
    return () => {
      cancelled = true
    }
  }, [enabled, reference])
  return { reference, unavailable }
}
