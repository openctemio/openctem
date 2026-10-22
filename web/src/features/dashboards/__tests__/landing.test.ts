import { describe, expect, it } from 'vitest'
import { parseRef, pickLanding, refKey } from '../landing'
import type { Dashboard } from '../api/dashboards.types'

const d = (id: string, extra: Partial<Dashboard> = {}): Dashboard => ({
  id,
  name: id,
  is_default: false,
  layout: [],
  ...extra,
})

describe('pickLanding', () => {
  const mine = [d('p1'), d('p2', { is_default: true })]
  const org = [d('o1'), d('o2', { is_org_default: true })]

  it('keeps the last choice while it exists', () => {
    expect(pickLanding(mine, org, { kind: 'organization', id: 'o1' })).toEqual({
      kind: 'organization',
      id: 'o1',
    })
  })

  it('drops a choice that no longer exists (or the viewer lost access to)', () => {
    expect(pickLanding(mine, [], { kind: 'organization', id: 'o1' })).toEqual({
      kind: 'personal',
      id: 'p2',
    })
  })

  it('own default, then organization default, then first organization, then first own', () => {
    expect(pickLanding(mine, org, null)).toEqual({ kind: 'personal', id: 'p2' })
    expect(pickLanding([d('p1')], org, null)).toEqual({ kind: 'organization', id: 'o2' })
    expect(pickLanding([d('p1')], [d('o1')], null)).toEqual({ kind: 'organization', id: 'o1' })
    expect(pickLanding([d('p1')], [], null)).toEqual({ kind: 'personal', id: 'p1' })
    expect(pickLanding([], [], null)).toBeNull()
  })

  it('round-trips a reference and refuses malformed ones', () => {
    expect(parseRef(refKey({ kind: 'personal', id: 'x' }))).toEqual({ kind: 'personal', id: 'x' })
    for (const bad of [null, '', 'x', 'ctem', 'other:x', 'personal:']) {
      expect(parseRef(bad)).toBeNull()
    }
  })
})
