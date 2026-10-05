/**
 * The root providers turn on zod's jitless mode (the CSP has no
 * 'unsafe-eval'), through zod's core config rather than `z` from 'zod' so
 * zod stays out of every page's first-load JS. The setting must still reach
 * the `z` that forms use.
 */
import { describe, expect, it } from 'vitest'
import { z } from 'zod'

describe('root providers', () => {
  it('enable zod jitless for the z that forms import', async () => {
    await import('@/app/providers')
    expect(z.config().jitless).toBe(true)
  })
})
