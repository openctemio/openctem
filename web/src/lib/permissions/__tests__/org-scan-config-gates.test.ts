import { describe, it, expect } from 'vitest'
import { passesRouteGate, routeGate, type ApiRouteKey } from '../can-mutate'

// Organization-wide scan configuration is owner/admin only on the API, so the
// console hides these controls from members instead of showing buttons that 403.
const ADMIN_ONLY: ApiRouteKey[] = [
  'PUT /api/v1/scan-profiles/{id}/quality-gate',
  'POST /api/v1/scan-profiles/{id}/set-default',
  'PATCH /api/v1/tools/settings',
  'PATCH /api/v1/tools/{id}/settings',
]

describe('organization-wide scan configuration route gates', () => {
  for (const key of ADMIN_ONLY) {
    it(`${key}: admin passes, member does not`, () => {
      const gate = routeGate(key)
      const perms = [...(gate.permissions ?? []), ...(gate.any_of ?? []).flat()]
      expect(passesRouteGate(gate, perms, 'admin')).toBe(true)
      expect(passesRouteGate(gate, perms, 'member')).toBe(false)
    })
  }
})
