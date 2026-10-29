import { describe, expect, it } from 'vitest'
import {
  adminCanElevate,
  adminHas,
  adminMayHave,
  elevationChoices,
  type AdminIdentity,
} from '../types'

const base: AdminIdentity = { id: 'a', email: 'a@x', name: 'A', role: 'readonly' }

describe('platform permissions in the console (RFC-134)', () => {
  it('reads the acting and maximum permissions the API sends', () => {
    const me: AdminIdentity = {
      ...base,
      roles: ['platform_viewer', 'support'],
      permissions: ['platform.tenants.read'],
      max_permissions: ['platform.tenants.read', 'platform.users.support'],
    }
    expect(adminHas(me, 'platform.users.support')).toBe(false)
    expect(adminMayHave(me, 'platform.users.support')).toBe(true)
    expect(adminHas(me, 'platform.admins.manage')).toBe(false)
    expect(adminCanElevate(me)).toBe(true)
    expect(elevationChoices(me)).toEqual(['support'])
  })

  it('offers no elevation when nothing more is held, or while elevated', () => {
    const viewer: AdminIdentity = {
      ...base,
      roles: ['platform_viewer'],
      permissions: ['platform.tenants.read'],
      max_permissions: ['platform.tenants.read'],
    }
    expect(adminCanElevate(viewer)).toBe(false)
    expect(
      adminCanElevate({ ...viewer, max_permissions: ['x'], elevated_until: '2030-01-01T00:00:00Z' })
    ).toBe(false)
  })

  it('lets an owner act as the admin role too', () => {
    expect(elevationChoices({ ...base, roles: ['platform_owner', 'support'] })).toEqual([
      'platform_owner',
      'platform_admin',
      'support',
    ])
  })

  it('falls back to the tier for an identity without permissions', () => {
    expect(adminHas({ ...base, role: 'ops_admin' }, 'platform.users.read')).toBe(true)
    expect(adminHas({ ...base, role: 'ops_admin' }, 'platform.admins.manage')).toBe(false)
    expect(adminHas({ ...base, role: 'super_admin' }, 'platform.admins.manage')).toBe(true)
    expect(adminHas(null, 'platform.console.read')).toBe(false)
  })
})
