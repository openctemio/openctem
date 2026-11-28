/**
 * An edge with waypoints passes through each of them and puts its label on
 * the middle one (the reserved slot), not halfway between its ends where a
 * node may stand.
 */
import { describe, it, expect } from 'vitest'
import { viaPath } from '../flow-edge'

describe('viaPath', () => {
  it('passes through every waypoint and labels the middle one', () => {
    const [d, lx, ly] = viaPath({ x: 0, y: 50 }, [{ x: 430, y: 192 }], { x: 680, y: 50 })
    expect(d.startsWith('M0,50')).toBe(true)
    expect(d).toContain(' 430,192 C')
    expect(d.endsWith(' 680,50')).toBe(true)
    expect([lx, ly]).toEqual([430, 192])
  })

  it('labels the middle of several waypoints', () => {
    const [, lx] = viaPath(
      { x: 0, y: 0 },
      [
        { x: 100, y: 10 },
        { x: 200, y: 10 },
        { x: 300, y: 10 },
      ],
      { x: 400, y: 0 }
    )
    expect(lx).toBe(200)
  })
})
