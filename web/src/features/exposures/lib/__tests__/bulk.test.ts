import { describe, expect, it } from 'vitest'

import { runPool, summarizeBulk } from '../bulk'

describe('runPool', () => {
  it('never runs more than the pool size at once', async () => {
    let inFlight = 0
    let peak = 0
    const ids = Array.from({ length: 23 }, (_, i) => `e${i}`)
    await runPool(
      ids,
      async () => {
        inFlight++
        peak = Math.max(peak, inFlight)
        await new Promise((r) => setTimeout(r, 2))
        inFlight--
      },
      5
    )
    expect(peak).toBe(5)
  })

  it('keeps going after a failure and reports every id', async () => {
    const results = await runPool(['a', 'b', 'c'], async (id) => {
      if (id === 'b') throw new Error('boom')
      return id
    })
    expect(results.map((r) => r.status)).toEqual(['fulfilled', 'rejected', 'fulfilled'])
    expect(summarizeBulk(results)).toEqual({ total: 3, succeeded: 2, pending: 0, failed: 1 })
  })

  it('counts pending approvals separately from applied changes', async () => {
    const results = await runPool(['a', 'b'], async (id) => ({ pending: id === 'a' }))
    expect(summarizeBulk(results, (r) => r.pending)).toEqual({
      total: 2,
      succeeded: 2,
      pending: 1,
      failed: 0,
    })
  })
})
