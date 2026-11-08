import { describe, expect, it } from 'vitest'
import { noiseSegments, NOISE_PARTS } from '../intake-viz'
import type { IntakeData } from '../types'

const noise = (over: Partial<IntakeData['noise']>): IntakeData['noise'] =>
  ({
    received: 0,
    new: 0,
    merged: 0,
    suppressed: 0,
    not_stored: 0,
    seen_again: 0,
    repeated: 0,
    outcomes: {},
    unaccounted: 0,
    ...over,
  }) as IntakeData['noise']

describe('noiseSegments', () => {
  it('draws suppressed as its own part and never subtracts it from New', () => {
    // Created and reopened 10, suppressed 4 (counted apart from created),
    // merged 6, not stored 2: 22 received.
    const { segments, removed } = noiseSegments(
      noise({ received: 22, new: 10, merged: 6, suppressed: 4, not_stored: 2 })
    )
    expect(segments.new).toBe(10)
    expect(segments.suppressed).toBe(4)
    const sum = NOISE_PARTS.reduce((acc, p) => acc + segments[p.key], 0)
    expect(sum).toBe(22)
    // Removed noise is everything that is not new or reopened, once.
    expect(removed).toBe(12)
  })

  it('never reports negative removed noise', () => {
    expect(noiseSegments(noise({ received: 1, new: 3 })).removed).toBe(0)
  })
})
