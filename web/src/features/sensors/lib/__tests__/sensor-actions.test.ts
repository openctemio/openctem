import { describe, expect, it } from 'vitest'
import { sensorActions, type SensorActionPerms } from '../sensor-actions'

const none: SensorActionPerms = { write: false, revoke: false, delete: false }
const admin: SensorActionPerms = { write: true, revoke: true, delete: true }

const names = ['edit', 'rotate', 'enable', 'disable', 'revoke', 'delete'] as const
const offered = (status: string, perms: SensorActionPerms) => {
  const a = sensorActions({ status: status as never }, perms)
  return names.filter((n) => a[n])
}

// Pinned to api/internal/infra/http/routes/scanning.go: update, regenerate-key,
// activate, deactivate need sensors:write; revoke needs sensors:write OR
// sensors:revoke; delete needs sensors:delete. service.go refuses to activate a
// revoked sensor.
describe('sensorActions', () => {
  it('always offers view and nothing else without permissions', () => {
    for (const s of ['active', 'disabled', 'pending', 'revoked']) {
      expect(offered(s, none)).toEqual([])
      expect(sensorActions({ status: s as never }, none).view).toBe(true)
    }
  })

  it('offers Enable only for a disabled sensor', () => {
    expect(offered('disabled', admin)).toContain('enable')
    for (const s of ['active', 'pending', 'revoked'])
      expect(offered(s, admin)).not.toContain('enable')
  })

  it('offers Disable only for an active sensor', () => {
    expect(offered('active', admin)).toContain('disable')
    for (const s of ['disabled', 'pending', 'revoked'])
      expect(offered(s, admin)).not.toContain('disable')
  })

  it('lets sensors:revoke alone revoke, but not edit or rotate', () => {
    expect(offered('active', { ...none, revoke: true })).toEqual(['revoke'])
  })

  it('lets sensors:write revoke without sensors:revoke', () => {
    expect(offered('active', { ...none, write: true })).toContain('revoke')
  })

  it('does not tie Revoke to sensors:delete', () => {
    expect(offered('active', { ...none, delete: true })).toEqual(['delete'])
  })

  it('offers a revoked sensor only View and Delete', () => {
    expect(offered('revoked', admin)).toEqual(['delete'])
    expect(offered('revoked', { ...admin, delete: false })).toEqual([])
  })
})
