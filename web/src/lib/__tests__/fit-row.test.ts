import { describe, it, expect } from 'vitest'
import { foldToFit } from '../fit-row'

// gap 4, "+N" 40, as the asset list's service facts.
const fold = (avail: number, widths: number[]) => foldToFit(avail, widths, 4, 40)

describe('foldToFit', () => {
  it('everything fits: no "+N", even when "+N" would not have fitted beside them', () => {
    expect(fold(200, [60, 60, 72])).toBe(3) // 60+4+60+4+72 = 200
  })

  it('folds before anything is cut, keeping room for "+N"', () => {
    // 36 (status) + 81 (port) + 125 (edge) + 56 = 310 > 256: status and port,
    // then "+N" (36+4+81+4+40 = 165); the edge chip (125) does not fit whole.
    expect(fold(256, [36, 81, 125, 56])).toBe(2)
  })

  it('never skips an item to fit a smaller one after it (order is priority)', () => {
    // After 36 and the 200 that does not fit, the 10 would fit, but it stays folded.
    expect(fold(120, [36, 200, 10])).toBe(1)
  })

  it('a row too narrow for the first item shows only "+N"', () => {
    expect(fold(60, [80, 20])).toBe(0)
  })

  it('no items, nothing to fold', () => {
    expect(fold(0, [])).toBe(0)
    expect(fold(100, [])).toBe(0)
  })

  it('an item exactly filling the room beside "+N" fits', () => {
    // 40 ("+N") + 50 + 4 = 94
    expect(fold(94, [50, 50])).toBe(1)
    expect(fold(93, [50, 50])).toBe(0)
  })
})
