import { describe, it, expect } from 'vitest'
import { participantsBase, participantsKey } from '../use-participants'

describe('participants paths', () => {
  it('addresses findings and tasks under their own routes', () => {
    expect(participantsBase('finding', 'f-1')).toBe('/api/v1/findings/f-1')
    expect(participantsBase('task', 't-1')).toBe('/api/v1/remediation/tasks/t-1')
    expect(participantsKey('finding', 'f-1')).toBe('/api/v1/findings/f-1/participants')
    expect(participantsKey('task', 't-1')).toBe('/api/v1/remediation/tasks/t-1/participants')
  })

  it('encodes the id so a crafted one cannot change the path', () => {
    expect(participantsBase('finding', '../x?y')).toBe('/api/v1/findings/..%2Fx%3Fy')
  })
})
