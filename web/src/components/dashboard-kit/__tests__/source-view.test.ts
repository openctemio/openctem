import { describe, expect, it } from 'vitest'
import { groupByInstance, healthNote, releasedNote } from '../source-view'
import type { IntakeSourceRow } from '../types'

// A translator that returns the English fallback with {vars} filled in.
const t = (_k: string, fb?: string, v?: Record<string, string | number>) =>
  (fb ?? '').replace(/\{(\w+)\}/g, (_m, k) => String(v?.[k] ?? ''))

const NOW = Date.now()
const ago = (ms: number) => new Date(NOW - ms).toISOString()
const MIN = 60_000
const DAY = 24 * 60 * MIN

function source(over: Partial<IntakeSourceRow>): IntakeSourceRow {
  return {
    id: 'sensor:nuclei',
    origin: 'sensor',
    tool: 'nuclei',
    receipts: 1,
    received: 1,
    created: 0,
    still_detected: 0,
    reopened: 0,
    closed: 0,
    suppressed: 0,
    not_stored: 0,
    last_at: ago(48 * MIN),
    last_status: 'completed',
    health: 'ok',
    expected_every_seconds: null,
    drill: null,
    ...over,
  }
}

describe('stale note', () => {
  it('speaks of the stale sender, not the freshest sender of the source', () => {
    const note = healthNote(
      t,
      { health: 'stale', last_at: ago(48 * MIN), health_last_at: ago(5 * DAY) },
      'en'
    )
    expect(note).toContain('Stale')
    expect(note).not.toContain('48 minutes')
    expect(note).toMatch(/5 days|5 days ago|last week|day/)
  })

  it('has no note for a healthy source', () => {
    expect(healthNote(t, { health: 'ok', last_at: ago(48 * MIN) }, 'en')).toBeNull()
  })

  it('the instance group takes the last receipt of its worst sender', () => {
    const sources = [
      source({
        instances: [
          { id: 'a', kind: 'sensor', name: 'a', received: 1, health: 'ok', last_at: ago(48 * MIN) },
          {
            id: 'a',
            kind: 'sensor',
            name: 'a',
            received: 1,
            health: 'stale',
            last_at: ago(4 * DAY),
          },
        ],
      }),
    ]
    const [g] = groupByInstance(t, sources)
    expect(g.health).toBe('stale')
    expect(g.health_last_at).toBe(sources[0].instances![1].last_at)
  })
})

describe('released note', () => {
  it('names the released reports, and nothing when there are none', () => {
    expect(releasedNote(t, 3)).toBe('Includes 3 released from quarantine')
    expect(releasedNote(t, 0)).toBe('')
  })
})
