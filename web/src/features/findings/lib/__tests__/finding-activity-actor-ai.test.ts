import { describe, it, expect } from 'vitest'

import { findingActor } from '../finding-activity-items'
import type { Activity } from '../../types'

const base: Activity = {
  id: 'a1',
  type: 'status_changed',
  actor: 'ai',
  createdAt: '2026-10-28T10:00:00Z',
}

describe('findingActor for AI rows', () => {
  it('names the AI analyst and its accountable owners from the provenance', () => {
    const actor = findingActor({
      ...base,
      metadata: {
        actorType: 'ai',
        ai: {
          analyst_id: 'an1',
          analyst_name: 'Triage bot',
          run_id: 'r1',
          accountable: [
            { kind: 'user', id: 'u1', name: 'Jamie' },
            { kind: 'team', id: 't1', name: 'AppSec' },
          ],
        },
      },
    })
    expect(actor.kind).toBe('ai')
    expect(actor.name).toBe('Triage bot')
    expect(actor.ai).toEqual({ name: 'Triage bot', accountable: ['Jamie', 'AppSec'] })
  })

  it('falls back to the plain AI assistant for rows without provenance', () => {
    const actor = findingActor({ ...base, metadata: { actorType: 'ai' } })
    expect(actor).toEqual({ name: 'AI assistant', kind: 'ai' })
  })

  it('ignores a provenance without a name', () => {
    const actor = findingActor({ ...base, metadata: { actorType: 'ai', ai: { run_id: 'r1' } } })
    expect(actor.ai).toBeUndefined()
  })
})
