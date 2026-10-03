import { describe, expect, it } from 'vitest'
import { unwrapPermissionSet } from '../use-permission-sets'
import type { PermissionSetWithDetails } from '../../types/permission-set.types'

const set = {
  id: 'ps-1',
  tenant_id: 't-1',
  slug: 'triage',
  name: 'Triage',
  set_type: 'custom',
  is_active: true,
  is_system: false,
  created_at: '2026-10-02T00:00:00Z',
  updated_at: '2026-10-02T00:00:00Z',
  items: [{ permission_id: 'findings:read', modification_type: 'add' }],
  permissions: ['findings:read'],
} as unknown as PermissionSetWithDetails

describe('unwrapPermissionSet', () => {
  it('reads the set GET /permission-sets/{id} returns at the top level', () => {
    expect(unwrapPermissionSet(set)).toBe(set)
  })

  it('still reads a set wrapped in permission_set', () => {
    expect(unwrapPermissionSet({ permission_set: set })).toBe(set)
  })

  it('is null before the response arrives', () => {
    expect(unwrapPermissionSet(undefined)).toBeNull()
  })
})
