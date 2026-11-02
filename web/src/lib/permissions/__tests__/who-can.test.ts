import { describe, expect, it } from 'vitest'
import en from '@/lib/i18n/dictionaries/en/common.json'
import vi from '@/lib/i18n/dictionaries/vi/common.json'
import { Permission } from '../constants'
import { heldByKey, rolesGranting, rolesGrantingAll } from '../who-can'

describe('who holds a permission', () => {
  it('names the built-in roles, most privileged first', () => {
    expect(rolesGranting(Permission.AuditRead)).toEqual(['owner', 'admin'])
    expect(rolesGranting(Permission.DashboardRead)).toEqual(['owner', 'admin', 'member', 'viewer'])
    expect(rolesGranting('made:up')).toEqual([])
  })

  it('all-of needs every permission, any-of needs one', () => {
    expect(rolesGrantingAll([Permission.AuditRead, Permission.DashboardRead])).toEqual([
      'owner',
      'admin',
    ])
    expect(rolesGrantingAll([Permission.AuditRead, Permission.DashboardRead], true)).toEqual([
      'owner',
      'admin',
      'member',
      'viewer',
    ])
    expect(rolesGrantingAll([])).toEqual([])
  })

  it('has an en and vi sentence for the holders of every permission', () => {
    for (const permission of Object.values(Permission)) {
      const key = heldByKey(rolesGranting(permission))
      expect(en, `${permission} -> ${key}`).toHaveProperty([key])
      expect(vi, `${permission} -> ${key}`).toHaveProperty([key])
    }
  })
})
