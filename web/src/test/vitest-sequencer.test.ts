import { describe, expect, it } from 'vitest'
import { planShards } from '../../vitest.sequencer'

const files = ['a.test.ts', 'b.test.ts', 'c.test.ts', 'd.test.ts', 'e.test.ts', 'f.test.ts']

describe('planShards', () => {
  it('puts every file on exactly one shard', () => {
    const shards = planShards(files, { 'a.test.ts': 50, 'c.test.ts': 7 }, 3)
    expect(shards.flat().sort()).toEqual([...files].sort())
  })

  it('balances by recorded duration, longest first', () => {
    const shards = planShards(
      files,
      {
        'a.test.ts': 100,
        'b.test.ts': 60,
        'c.test.ts': 40,
        'd.test.ts': 40,
        'e.test.ts': 30,
        'f.test.ts': 30,
      },
      3
    )
    expect(shards[0][0]).toBe('a.test.ts')
    expect(shards[1][0]).toBe('b.test.ts')
    const total = (s: string[]) =>
      s.reduce(
        (n, f) =>
          n +
          (
            {
              'a.test.ts': 100,
              'b.test.ts': 60,
              'c.test.ts': 40,
              'd.test.ts': 40,
              'e.test.ts': 30,
              'f.test.ts': 30,
            } as Record<string, number>
          )[f],
        0
      )
    const loads = shards.map(total)
    expect(Math.max(...loads) - Math.min(...loads)).toBeLessThanOrEqual(50)
  })

  it('is the same plan for the same input', () => {
    const d = { 'b.test.ts': 9, 'a.test.ts': 9 }
    expect(planShards(files, d, 2)).toEqual(planShards([...files].reverse(), d, 2))
  })

  it('ignores junk durations and unknown files', () => {
    const shards = planShards(
      files,
      { 'a.test.ts': -3, 'b.test.ts': Number.NaN, 'zzz.test.ts': 1e9 },
      2
    )
    expect(shards.flat().sort()).toEqual([...files].sort())
  })

  it('works with no durations at all', () => {
    expect(planShards(files, {}, 4).flat().sort()).toEqual([...files].sort())
  })
})
