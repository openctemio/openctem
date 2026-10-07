import { describe, expect, it } from 'vitest'
import { actorLabel } from '../actor'

describe('actorLabel', () => {
  it('names a member, a former member and the platform; never a raw id', () => {
    expect(actorLabel({ kind: 'user', id: '019d', name: 'Nguyen Manh' })).toBe('Nguyen Manh')
    expect(actorLabel({ kind: 'user', id: '019d', former_member: true })).toBe('Former member')
    expect(actorLabel({ kind: 'system', code: 'upgrade_wildcard_split' })).toBe(
      'OpenCTEM upgrade (wildcard rule change)'
    )
    expect(actorLabel({ kind: 'system', code: 'unknown' })).toBe('OpenCTEM')
    expect(actorLabel({ kind: 'user', id: '019d' })).toBe('Member')
    expect(actorLabel(undefined)).toBe('')
  })
})
